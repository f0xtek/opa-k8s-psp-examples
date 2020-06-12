package kubernetes.admission

# deny images that do not come from a trusted registry
deny[msg] {
    input.request.kind.kind == "Deployment"
    image := input.request.object.spec.template.spec.containers[_].image
    not startswith(image, "registry.example.com:5000/")
    msg := sprintf("Image %v comes from untrusted registry.", [image])
}

# deny privileged containers
deny[msg] {
    input.request.kind.kind == "Deployment"
    container := input.request.object.spec.template.spec.containers[_]
    container.securityContext.privileged
    msg := sprintf("Container %v runs in privileged mode. Please specify the 'privileged: false' option in the container securityContext.'", [container.name])
}

# deny containers running as root
deny[msg] {
    input.request.kind.kind == "Deployment"
    container := input.request.object.spec.template.spec.containers[_]
    not container.securityContext.RunAsNonRoot
    msg := sprintf("Container %v running as a root. Please specify the 'RunAsNonRoot: true' option int he container securityContext.'", [container.name])
}

# deny containers that allow privilege escalation
deny[msg] {
    input.request.kind.kind == "Deployment"
    container := input.request.object.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation
    msg := sprintf("Container %v allows privilege escalation. Please specify the 'allowPrivilegeEscalation: false' option in the container securityContext.", [container.name])
}

# deny containers that do not drop kernel capabilities
deny[msg] {
    input.request.kind.kind == "Deployment"
    container := input.request.object.spec.template.spec.containers[_]
    not container.securityContext.capabilties.drop[0] == "ALL"
    msg := sprintf("Container %v allows unnecessary kernel capabilities. Please add the capabilities.drop: ['ALL'] option to the container securityContext. Specific capabilities can be added, if required, using the capabilities.add option in the container securityContext.", [container.name])
}
