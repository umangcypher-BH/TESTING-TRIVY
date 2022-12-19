package user.dockerfile.ID003

__rego_metadata__ := {
        "id": "ID003",
        "title": "HTTP not allowed",
        "severity": "CRITICAL",
        "type": "Dockerfile Custom Check",
        "description": "HTTP should not be used. \n\n\n\n.",
}

__rego_input__ := {"selector": [{"type": "dockerfile"}]}


result(msg, cmd) = result {
        result := {
                "msg": msg,
                "startline": object.get(cmd, "StartLine", 0),
                "endline": object.get(cmd, "EndLine", 0),
                "filepath": object.get(cmd, "Path", ""),
        }
}

fail_http_check[add] {
        add := input.Stages[_].Commands[_]
        add.Cmd == "add"
        startswith(add.Value[0], "http://")
}


deny[res] {
        cmd := fail_http_check[_]
        msg := "download from http:// not allowed: "
        res := result(msg, cmd)
}
