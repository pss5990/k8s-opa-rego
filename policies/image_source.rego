package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    image := input.request.object.spec.containers[_].image
    name := input.request.object.metadata.name
    not registry_whitelisted(image,whitelisted_registries)
    msg := sprintf("pod %q has invalid registry %q", [name, image])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    initContainers := input.request.object.spec.initContainers
    count(initContainers) > 0
    print("checking init containers")
    image := initContainers[_].image
    name := input.request.object.metadata.name
    not registry_whitelisted(image,whitelisted_registries)
    msg := sprintf("pod %q has invalid registry %q", [name, image])
}

whitelisted_registries = {registry |
    registries = [
        "602401143452.dkr.ecr.amazonaws.com"
    ]
    registry = registries[_]
}

registry_whitelisted(str, patterns) {
    registry_matches(str, patterns[_])
}

registry_matches(str, pattern) {
    startswith(str, pattern)
}
