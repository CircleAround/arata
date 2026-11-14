# 監査を回すリポジトリの GitHub の設定。arata repo init が書き出したファイル (ADR 0059)。手で直さない。
#
# 宣言に持つのは、セキュリティに効く項目だけ。説明・トピック・マージの方式などは、画面で自由に変えてよい (ignore_changes)。
# 当てるのは人が手元で行う (README.md の 3)。認証は環境変数 GITHUB_TOKEN で渡す。state は手元に置き、git には入れない。
#
#   GITHUB_TOKEN="$(gh auth token)" terraform -chdir=github init
#   GITHUB_TOKEN="$(gh auth token)" terraform -chdir=github apply

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "= @@PROVIDER_VERSION@@"
    }
  }
}

provider "github" {
  owner = local.owner
}

locals {
  owner       = "@@OWNER@@"
  repository  = "@@REPO@@"
  environment = "audit" # ワークフローの environment: と、runner.yaml の GitHubEnvironment と同じ名前
  branch      = "main"  # デプロイできるブランチ。runner.yaml の GitHubBranch と同じ名前
}

variable "required_approving_review_count" {
  description = "main への PR に要る承認の数。1 人で運用するなら 0。2 人以上いるなら 1 以上にする (1 人では main を変えられなくなる)"
  type        = number
  default     = 0

  validation {
    condition     = var.required_approving_review_count >= 0 && var.required_approving_review_count <= 10 && floor(var.required_approving_review_count) == var.required_approving_review_count
    error_message = "0 から 10 の整数にする。"
  }
}

# 非公開にし、fork を禁止する。allowlist にはアカウント ID や ARN が入る。
# 新しく作るときは、最初のコミットを GitHub に作らせる (auto_init)。空のリポジトリには PR を出せないので、一式は最初の PR で入れる。
# 既にあるリポジトリは、先に取り込む: terraform -chdir=github import github_repository.audit @@REPO@@
resource "github_repository" "audit" {
  name          = local.repository
  visibility    = "private"
  allow_forking = false
  auto_init     = true

  lifecycle {
    # リポジトリそのものを消さない (terraform destroy や、この宣言の消し忘れで)
    prevent_destroy = true

    # セキュリティに効かない項目は宣言に持たない。画面で変えても、ずれとして扱わない
    ignore_changes = [
      allow_auto_merge,
      allow_merge_commit,
      allow_rebase_merge,
      allow_squash_merge,
      allow_update_branch,
      archive_on_destroy,
      auto_init,
      delete_branch_on_merge,
      description,
      gitignore_template,
      has_discussions,
      has_issues,
      has_projects,
      has_wiki,
      homepage_url,
      is_template,
      license_template,
      merge_commit_message,
      merge_commit_title,
      squash_merge_commit_message,
      squash_merge_commit_title,
      topics,
      web_commit_signoff_required,
    ]
  }
}

# 既定のブランチ (main) の保護。main に入れられる人 = 実行用ロールと秘密を使える人、なので、ここが権限の境界になる。
# 迂回できる主体 (bypass_actors) は置かない。
resource "github_repository_ruleset" "default_branch" {
  name        = "arata-default-branch"
  repository  = github_repository.audit.name
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  rules {
    deletion         = true # 削除の禁止
    non_fast_forward = true # force push の禁止

    # PR 必須
    pull_request {
      required_approving_review_count = var.required_approving_review_count
    }

    # 必須のチェック。arata-check.yml のジョブ (check): 形の誤った設定と allowlist.yaml を main に入れない
    required_status_checks {
      required_check {
        context = "check"
      }
    }
  }
}

# 使える action を、GitHub 製と aws-actions/configure-aws-credentials だけにし、commit SHA での固定を必須にする。
# ワークフローに action を足すときは、ここにも足す (足さないと、ワークフローが起動しない)。
resource "github_actions_repository_permissions" "audit" {
  repository           = github_repository.audit.name
  enabled              = true
  allowed_actions      = "selected"
  sha_pinning_required = true

  allowed_actions_config {
    github_owned_allowed = true
    verified_allowed     = false
    patterns_allowed     = ["aws-actions/configure-aws-credentials@*"]
  }
}

# GITHUB_TOKEN の既定は read。Actions に PR を承認させない。
resource "github_workflow_repository_permissions" "audit" {
  repository                       = github_repository.audit.name
  default_workflow_permissions     = "read"
  can_approve_pull_request_reviews = false
}

# 秘密を置く environment。デプロイできるブランチを main だけにする: ほかのブランチのジョブには、秘密も OIDC のトークンも渡らない。
# 必ずワークフローより先に作る (無い environment を参照するワークフローが動くと、制限なしで自動で作られる。ADR 0057)。
# レビュー担当と待ち時間は付けない (定時の実行が、承認を待って止まる)。
resource "github_repository_environment" "audit" {
  repository  = github_repository.audit.name
  environment = local.environment

  deployment_branch_policy {
    protected_branches     = false
    custom_branch_policies = true
  }
}

resource "github_repository_environment_deployment_policy" "audit_branch" {
  repository     = github_repository.audit.name
  environment    = github_repository_environment.audit.environment
  branch_pattern = local.branch
}
