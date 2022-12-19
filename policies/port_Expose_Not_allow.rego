package user.dockerfile.ID002

__rego_metadata__ := {
        "id": "ID002",
        "title": "Port 20/22/23 exposed",
        "short_code": "no-ssh-port",
        "severity": "CRITICAL",
        "type": "Dockerfile Security Check",
        "description": "Exposing port Port 22/69/25/23/53/139/137/445  might allow users to attacks  into the container.\n\nrecommended_actions: Remove 'EXPOSE Port' statement from the Dockerfile",
}

__rego_input__ := {
        "combine": false,
        "selector": [{"type": "dockerfile"}],
}

# deny_list contains the port numbers which needs to be denied.
denied_ports := ["22", "22/tcp", "22/udp", "69", "69/udp", "25", "25/tcp", "23", "23/tcp", "53", "53/tcp", "53/udp", "139", "139/tcp", "137", "137/udp", "445", "445/tcp"]

# fail_port_check is true if the Dockerfile contains an expose statement for value 22
result(msg, cmd) = result {
        result := {
                "msg": msg,
                "startline": object.get(cmd, "StartLine", 0),
                "endline": object.get(cmd, "EndLine", 0),
                "filepath": object.get(cmd, "Path", ""),
        }
}
fail_port_check[expose] {
        expose := input.Stages[_].Commands[_]
        expose.Cmd == "expose"
#       expose := docker.expose[_]
#       expose := docker.expose[_]
#       #expose.Value[_] == denied_ports[_]
        expose.Value[_] == denied_ports[_]
}

deny[res] {
        cmd := fail_port_check[_]
        msg := "Port 22/69/25/23/53/139/137/445 should not be exposed in Dockerfile"
        res := result(msg, cmd)
}

