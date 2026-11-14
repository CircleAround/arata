# 秘密の箱。arata repo init が書き出したファイル (ADR 0059)。手で直さない。
#
# ワークフローが使う秘密の名前を、environment (audit) に仮の値で作る。値を入れる人は、画面で名前を迷わない。
# 既にある秘密には書かない:
#   - 既にある名前は、import で state に取り込むだけ (読むだけで、値は state に入らない)
#   - 無い名前だけを、仮の値で作る
#   - 値の変更は見ない (ignore_changes)。人が本物の値を入れた後に当て直しても、何も変わらない
#   - 消さない (prevent_destroy)
#
# 当てるのは github/ の後 (environment が無いと、一覧を読めずにエラーで止まる。README.md の 4)。
# 計画 (plan) に「作る」と出た名前が、本当にまだ無いことを確かめてから承認する。
# 一覧を読むのは計画のときなので、その後に同じ名前の秘密を誰かが入れると、仮の値で置き換わる。
#
#   GITHUB_TOKEN="$(gh auth token)" terraform -chdir=github/secrets init
#   GITHUB_TOKEN="$(gh auth token)" terraform -chdir=github/secrets apply

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "= 6.13.0"
    }
  }
}

provider "github" {
  owner = local.owner
}

locals {
  owner       = "example-org"
  repository  = "security-audit"
  environment = "audit"

  # ワークフローが使う秘密の名前 (.github/workflows の secrets.* と同じ)
  names = toset([
    "ARATAM_SLACK_BOT_TOKEN",
    "ARATAM_SLACK_URGENT_WEBHOOK",
    "ARATAM_SLACK_WEBHOOK",
    "ARATA_ALERT_WEBHOOK",
    "ARATA_AUDIT_ROLE_ARNS",
    "ARATA_RUNNER_ROLE_ARN",
  ])

  # 仮の値。秘密ではない。ARN・JSON・URL・トークンのどの形でもなく、ワークフローはこの値を見たら名前を出して止まる
  # (.github/scripts/arata-secret-check.sh の PLACEHOLDER と同じ文字列)
  placeholder = "arata-placeholder-not-set-yet"

  existing = toset(data.github_actions_environment_secrets.audit.secrets[*].name)
}

# environment の秘密の名前の一覧 (値は読めない)
data "github_actions_environment_secrets" "audit" {
  name        = local.repository
  environment = local.environment
}

# 既にある名前は、作らずに取り込む
import {
  for_each = setintersection(local.names, local.existing)
  to       = github_actions_environment_secret.box[each.key]
  id       = "${local.repository}:${local.environment}:${each.key}"
}

resource "github_actions_environment_secret" "box" {
  for_each = local.names

  repository  = local.repository
  environment = local.environment
  secret_name = each.key
  value       = local.placeholder

  lifecycle {
    ignore_changes  = [value]
    prevent_destroy = true
  }
}

output "created_with_placeholder" {
  description = "この実行の計画の時点で無かった名前 (仮の値で箱を作った。本物の値を入れる)"
  value       = sort(tolist(setsubtract(local.names, local.existing)))
}
