package main

import data.lib.kubernetes

violation[msg] {
	kubernetes.containers[container]
	[image_name, "latest"] = kubernetes.split_image(container.image)
	msg = kubernetes.format(sprintf("%s in the %s %s has an image, %s, using the latest tag", [container.name, kubernetes.kind, image_name, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	not container.resources.requests.memory
	msg = kubernetes.format(sprintf("%s in the %s %s does not have a memory request set", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	not container.resources.requests.cpu
	msg = kubernetes.format(sprintf("%s in the %s %s does not have a CPU request set", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	not container.resources.limits.memory
	msg = kubernetes.format(sprintf("%s in the %s %s does not have a memory limit set", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	not container.resources.limits.cpu
	msg = kubernetes.format(sprintf("%s in the %s %s does not have a CPU limit set", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	kubernetes.added_capability(container, "CAP_SYS_ADMIN")
	msg = kubernetes.format(sprintf("%s in the %s %s has SYS_ADMIN capabilities", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	not kubernetes.dropped_capability(container, "all")
	msg = kubernetes.format(sprintf("%s in the %s %s doesn't drop all capabilities", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	container.securityContext.privileged
	msg = kubernetes.format(sprintf("%s in the %s %s is privileged", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	kubernetes.no_read_only_filesystem(container)
	msg = kubernetes.format(sprintf("%s in the %s %s is not using a read only root filesystem", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	kubernetes.privilege_escalation_allowed(container)
	msg = kubernetes.format(sprintf("%s in the %s %s allows privilege escalation", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	not container.securityContext.runAsNonRoot = true
	msg = kubernetes.format(sprintf("%s in the %s %s is running as root", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
	kubernetes.containers[container]
	container.securityContext.runAsUser < 10000
	msg = kubernetes.format(sprintf("%s in the %s %s has a UID of less than 10000", [container.name, kubernetes.kind, kubernetes.name]))
}

violation[msg] {
  input.kind = "Deployment"
  not input.metadata.labels.version
  msg = "Expected Deployment to have version as a label"
}

violation[msg] {
  input.kind = "Deployment"
  not input.metadata.labels.app
  msg = "Expected Deployment to have app as a label"
}
