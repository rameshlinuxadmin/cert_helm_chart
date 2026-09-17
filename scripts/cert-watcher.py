import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from kubernetes import client, config, watch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
)
logger = logging.getLogger(__name__)

CERTIFICATES_RAW = os.getenv("CERTIFICATES", "[]")
RESTART_DEPLOYMENT_NAME = os.getenv("RESTART_DEPLOYMENT_NAME")
RESTART_DEPLOYMENT_NAMESPACE = os.getenv("RESTART_DEPLOYMENT_NAMESPACE")

AWS_REGION = os.getenv("AWS_REGION")
EVENT_BUS_NAME = os.getenv("EVENT_BUS_NAME")
EVENT_SOURCE = os.getenv("EVENT_SOURCE")
EVENT_DETAIL_TYPE = os.getenv("EVENT_DETAIL_TYPE")

ROLLOUT_TIMEOUT_SECONDS = int(os.getenv("ROLLOUT_TIMEOUT_SECONDS", "300"))
ROLLOUT_POLL_INTERVAL_SECONDS = int(os.getenv("ROLLOUT_POLL_INTERVAL_SECONDS", "5"))

@dataclass(frozen=True)
class CertificateConfig:
    cert_name: str
    cert_namespace: str
    cert_secret_name: str

def load_kubernetes_config():
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local Kubernetes kubeconfig")

def parse_certificates() -> List[CertificateConfig]:
    try:
        items = json.loads(CERTIFICATES_RAW)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid CERTIFICATES JSON: {exc}") from exc

    if not isinstance(items, list) or not items:
        raise ValueError("CERTIFICATES must be a non-empty JSON array")

    parsed = []
    seen = set()

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"CERTIFICATES[{i}] must be an object")

        cert_name = item.get("CERT_NAME")
        cert_namespace = item.get("CERT_NAMESPACE")
        cert_secret_name = item.get("CERT_SECRET_NAME")

        if not cert_name or not cert_namespace or not cert_secret_name:
            raise ValueError(
                f"CERTIFICATES[{i}] must include CERT_NAME, CERT_NAMESPACE, CERT_SECRET_NAME"
            )

        key = (cert_name, cert_namespace, cert_secret_name)
        if key in seen:
            logger.warning("Duplicate certificate config ignored: %s", key)
            continue

        seen.add(key)
        parsed.append(
            CertificateConfig(
                cert_name=cert_name,
                cert_namespace=cert_namespace,
                cert_secret_name=cert_secret_name,
            )
        )

    return parsed

def create_events_client():
    if not AWS_REGION:
        raise ValueError("Missing required env var: AWS_REGION")
    return boto3.client("events", region_name=AWS_REGION)

def publish_certificate_changed_event(cert: CertificateConfig, events_client) -> bool:
    detail = {
        "namespace": cert.cert_namespace,
        "secretName": cert.cert_secret_name,
        "certificateName": cert.cert_name,
        "changedField": "tls.crt",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        response = events_client.put_events(
            Entries=[
                {
                    "EventBusName": EVENT_BUS_NAME,
                    "Source": EVENT_SOURCE,
                    "DetailType": EVENT_DETAIL_TYPE,
                    "Detail": json.dumps(detail),
                }
            ]
        )

        failed_count = response.get("FailedEntryCount", 0)
        if failed_count > 0:
            logger.error(
                "Failed to publish event for cert=%s secret=%s response=%s",
                cert.cert_name,
                cert.cert_secret_name,
                response,
            )
            return False

        logger.info(
            "Published CertificateChanged event for cert=%s namespace=%s secret=%s",
            cert.cert_name,
            cert.cert_namespace,
            cert.cert_secret_name,
        )
        return True

    except (BotoCoreError, ClientError) as exc:
        logger.exception(
            "Error publishing event for cert=%s secret=%s: %s",
            cert.cert_name,
            cert.cert_secret_name,
            exc,
        )
        return False

def wait_for_deployment_rollout(
    apps_v1: client.AppsV1Api,
    deployment_name: str,
    deployment_namespace: str,
    timeout_seconds: int = ROLLOUT_TIMEOUT_SECONDS,
    poll_interval_seconds: int = ROLLOUT_POLL_INTERVAL_SECONDS,
) -> bool:
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        deployment = apps_v1.read_namespaced_deployment(
            name=deployment_name,
            namespace=deployment_namespace,
        )

        spec_replicas = deployment.spec.replicas or 0
        status = deployment.status
        observed_generation = status.observed_generation or 0
        generation = deployment.metadata.generation or 0
        updated_replicas = status.updated_replicas or 0
        ready_replicas = status.ready_replicas or 0
        available_replicas = status.available_replicas or 0

        if (
            observed_generation >= generation
            and updated_replicas == spec_replicas
            and ready_replicas == spec_replicas
            and available_replicas == spec_replicas
        ):
            logger.info(
                "Deployment rollout complete for %s/%s",
                deployment_namespace,
                deployment_name,
            )
            return True

        logger.info(
            "Waiting for rollout of %s/%s: generation=%s observed=%s updated=%s ready=%s available=%s desired=%s",
            deployment_namespace,
            deployment_name,
            generation,
            observed_generation,
            updated_replicas,
            ready_replicas,
            available_replicas,
            spec_replicas,
        )
        time.sleep(poll_interval_seconds)

    logger.error(
        "Timed out waiting for rollout of %s/%s after %s seconds",
        deployment_namespace,
        deployment_name,
        timeout_seconds,
    )
    return False

def restart_deployment() -> bool:
    apps_v1 = client.AppsV1Api()

    restart_time = datetime.now(timezone.utc).isoformat()

    patch_body = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": restart_time
                    }
                }
            }
        }
    }

    try:
        apps_v1.patch_namespaced_deployment(
            name=RESTART_DEPLOYMENT_NAME,
            namespace=RESTART_DEPLOYMENT_NAMESPACE,
            body=patch_body,
        )

        logger.info(
            "Triggered rollout restart for deployment %s/%s at %s",
            RESTART_DEPLOYMENT_NAMESPACE,
            RESTART_DEPLOYMENT_NAME,
            restart_time,
        )

        return wait_for_deployment_rollout(
            apps_v1=apps_v1,
            deployment_name=RESTART_DEPLOYMENT_NAME,
            deployment_namespace=RESTART_DEPLOYMENT_NAMESPACE,
        )

    except client.exceptions.ApiException as exc:
        logger.error(
            "Failed to restart deployment %s/%s: %s",
            RESTART_DEPLOYMENT_NAMESPACE,
            RESTART_DEPLOYMENT_NAME,
            exc,
        )
        return False

def watch_secret_for_certificate(cert: CertificateConfig, events_client):
    v1 = client.CoreV1Api()
    w = watch.Watch()

    try:
        current_secret = v1.read_namespaced_secret(
            name=cert.cert_secret_name,
            namespace=cert.cert_namespace,
        )

        previous_tls_crt = (
            current_secret.data.get("tls.crt")
            if current_secret.data
            else None
        )
        resource_version = current_secret.metadata.resource_version

        logger.info(
            "Initial state loaded for cert=%s secret=%s/%s rv=%s",
            cert.cert_name,
            cert.cert_namespace,
            cert.cert_secret_name,
            resource_version,
        )

    except client.exceptions.ApiException as exc:
        logger.error(
            "Unable to read initial Secret for cert=%s secret=%s/%s: %s",
            cert.cert_name,
            cert.cert_namespace,
            cert.cert_secret_name,
            exc,
        )
        raise

    while True:
        try:
            logger.info(
                "Starting watch for cert=%s secret=%s/%s",
                cert.cert_name,
                cert.cert_namespace,
                cert.cert_secret_name,
            )

            stream = w.stream(
                v1.list_namespaced_secret,
                namespace=cert.cert_namespace,
                field_selector=f"metadata.name={cert.cert_secret_name}",
                resource_version=resource_version,
                timeout_seconds=300,
            )

            for event in stream:
                event_type = event["type"]
                secret = event["object"]

                if not secret:
                    continue

                resource_version = secret.metadata.resource_version

                if event_type == "DELETED":
                    logger.warning(
                        "Secret deleted for cert=%s secret=%s/%s",
                        cert.cert_name,
                        cert.cert_namespace,
                        cert.cert_secret_name,
                    )
                    continue

                if event_type != "MODIFIED":
                    continue

                current_tls_crt = (
                    secret.data.get("tls.crt")
                    if secret.data
                    else None
                )

                if current_tls_crt == previous_tls_crt:
                    logger.debug(
                        "No tls.crt change for cert=%s secret=%s/%s",
                        cert.cert_name,
                        cert.cert_namespace,
                        cert.cert_secret_name,
                    )
                    continue

                logger.info(
                    "tls.crt changed for cert=%s secret=%s/%s",
                    cert.cert_name,
                    cert.cert_namespace,
                    cert.cert_secret_name,
                )

                restart_success = restart_deployment()

                if not restart_success:
                    logger.error(
                        "Deployment restart/rollout failed for cert=%s; retaining previous tls.crt for retry",
                        cert.cert_name,
                    )
                    continue

                event_success = publish_certificate_changed_event(
                    cert,
                    events_client,
                )

                if event_success:
                    previous_tls_crt = current_tls_crt
                else:
                    logger.error(
                        "Event publish failed for cert=%s after successful rollout; retaining previous tls.crt for retry",
                        cert.cert_name,
                    )

        except client.exceptions.ApiException as exc:
            logger.error(
                "Kubernetes API error for cert=%s secret=%s/%s: %s",
                cert.cert_name,
                cert.cert_namespace,
                cert.cert_secret_name,
                exc,
            )

            if exc.status == 410:
                logger.info(
                    "ResourceVersion expired for cert=%s; resetting watch",
                    cert.cert_name,
                )
                resource_version = "0"

        except Exception as exc:
            logger.exception(
                "Unexpected watcher error for cert=%s secret=%s/%s: %s",
                cert.cert_name,
                cert.cert_namespace,
                cert.cert_secret_name,
                exc,
            )

        logger.info(
            "Watch stopped for cert=%s; reconnecting in 5 seconds",
            cert.cert_name,
        )
        time.sleep(5)

def main():
    if not RESTART_DEPLOYMENT_NAME or not RESTART_DEPLOYMENT_NAMESPACE:
        raise ValueError(
            "Missing required env vars: RESTART_DEPLOYMENT_NAME, RESTART_DEPLOYMENT_NAMESPACE"
        )

    if not EVENT_BUS_NAME or not EVENT_SOURCE or not EVENT_DETAIL_TYPE:
        raise ValueError(
            "Missing required env vars: EVENT_BUS_NAME, EVENT_SOURCE, EVENT_DETAIL_TYPE"
        )

    certificates = parse_certificates()
    events_client = create_events_client()

    logger.info(
        "Starting certificate watcher for %d certificate(s): %s",
        len(certificates),
        [c.cert_name for c in certificates],
    )

    load_kubernetes_config()

    threads = []
    for cert in certificates:
        t = threading.Thread(
            target=watch_secret_for_certificate,
            args=(cert, events_client),
            name=f"watch-{cert.cert_name}",
            daemon=False,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
