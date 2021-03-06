package kubernetes.admission

deny[msg] {
    # apply policy to all Pod resources
    input.request.kind.kind == "Pod"
    # get all containers in the Pod
    container := input.request.object.spec.containers[_]
    # for each container's securityContext, check the privileged field
    container.securityContext.privileged
    # if the privileged field is true, return the following message
    msg := sprintf("Container %v runs in privileged mode.", [container.name])
}

