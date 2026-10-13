package main
# Default Conftest policies (OPA/Rego) applied to GitHub Actions workflows, Dockerfiles, Terraform JSON and
# docker-compose. Projects extend by adding their own .rego under rego_policy_path.

triggers := object.get(input, "on", object.get(input, "true", {}))  # YAML 1.1 parses `on:` as the boolean key true

has_prt if { triggers.pull_request_target }
has_prt if { triggers == "pull_request_target" }
has_prt if { some t in triggers; t == "pull_request_target" }

deny contains msg if {
  has_prt
  some job in input.jobs
  some step in job.steps
  contains(step.uses, "actions/checkout")
  contains(sprintf("%v", [step["with"].ref]), "head")
  msg := "GitHub Actions: pull_request_target checks out the PR head (pwn request)"
}

deny contains msg if {
  some job in input.jobs
  some step in job.steps
  regex.match(`uses:\s*[\w.-]+/[\w./-]+@(v\d+|main|master|latest)\b`, sprintf("uses: %v", [step.uses]))
  not startswith(step.uses, "./")
  msg := sprintf("GitHub Actions: action %v is not pinned to a commit SHA", [step.uses])
}

deny contains msg if {
  input.permissions == "write-all"
  msg := "GitHub Actions: workflow requests write-all permissions"
}

deny contains msg if {
  some job in input.jobs
  job.permissions == "write-all"
  msg := "GitHub Actions: job requests write-all permissions"
}

deny contains msg if {
  some service_name, service in input.services
  service.privileged == true
  msg := sprintf("docker-compose: service %v runs privileged", [service_name])
}

deny contains msg if {
  some service_name, service in input.services
  some v in service.volumes
  contains(v, "/var/run/docker.sock")
  msg := sprintf("docker-compose: service %v mounts the Docker socket", [service_name])
}

deny contains msg if {
  some r in input.resource.aws_s3_bucket
  some name, b in r
  b.acl == "public-read"
  msg := sprintf("terraform: S3 bucket %v has a public ACL", [name])
}

deny contains msg if {
  some r in input.resource.aws_security_group
  some name, sg in r
  some ing in sg.ingress
  some c in ing.cidr_blocks
  c == "0.0.0.0/0"
  ing.from_port == 22
  msg := sprintf("terraform: security group %v exposes SSH to the world", [name])
}

deny contains msg if {
  some cmd in input
  cmd.Cmd == "run"
  regex.match(`(curl|wget)[^|]*\|\s*(ba)?sh`, concat(" ", cmd.Value))
  msg := "Dockerfile: RUN pipes a download into a shell"
}

deny contains msg if {
  some cmd in input
  cmd.Cmd == "user"
  cmd.Value[0] == "root"
  msg := "Dockerfile: USER root"
}

deny contains msg if {
  some cmd in input
  cmd.Cmd == "from"
  not contains(cmd.Value[0], "@sha256:")
  not contains(cmd.Value[0], "scratch")
  msg := sprintf("Dockerfile: base image %v not pinned by digest", [cmd.Value[0]])
}
