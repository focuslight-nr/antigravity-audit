# ANTIGRAVITY-AUDIT

`antigravity-audit` は、**Antigravity**（Google DeepMind エージェント環境）のローカル設定を読み取り専用で監査する Windows（PowerShell）および macOS（Zsh）用のセキュリティ点検ツールです。

ローカルおよびリモートの MCP サーバ連携、Lifecycle Hooks、プラグイン、登録されたワークスペースプロジェクト、信頼済みフォルダ、カスタムスキルやルール、セキュリティおよびサンドボックスポリシー、CLI / IDE 設定、機密認証情報ファイル、プロセス実行状況、およびデータ保持（リテンション）状態をチェックし、セキュリティ影響度に応じて `WARN`（警告）、`REVIEW`（確認推奨）、`INFO`（情報）の3段階で報告します。

> **非公式プロジェクト。** Google または DeepMind による提供、承認、スポンサー、保守を受けているものではありません。

本ツールは [claude-audit](../claude-audit) および [codex-audit](../codex-audit) の姉妹ツールであり、共通の出力スキーマを採用しているため、統合ダッシュボード [audit-viewer](../audit-viewer) 上で結果を一覧表示したり日時比較したりすることが可能です。

## 特徴

- **読み取り専用**: 設定ファイルやプロジェクトファイルを変更・削除することは一切ありません。
- **依存最小**: 外部の依存パッケージを必要とせず、Windows の標準 PowerShell または macOS の標準 Zsh で直接動作します（macOS の詳細 JSON 解析には `jq` を推奨します）。
- **認証情報・トークンの自動マスク**: `oauth_creds.json` や環境変数等に含まれるセンシティブな OAuth トークン、API キー、パスワード等をレポート出力時に自動的に `[REDACTED]` でマスクします。
- **スナップショット差分比較**: `--diff BASELINE.json` により、過去の監査スナップショットからの設定変更をすばやく検出・比較できます。
- **CI/ゲート連携**: `--fail-on warn|review` オプションにより、特定の重大度が存在する場合に非ゼロの終了コードで終了させることができ、コミット前チェックや自動スクリプトでの利用に適しています。

## 監査対象

| セクション | 監査内容 |
|---|---|
| Config | `settings.json`、Antigravity 2.0 アプリ設定、および CLI 設定（`antigravity-cli/settings.json`）のモデル指定や基本構成を点検。 |
| Security Settings | **重要セキュリティポリシーの点検**: ツール自動実行ポリシー（`always-proceed` は `WARN`）、ターミナルサンドボックス設定（無効化 `sandbox.enabled: false` は `WARN`、ネットワーク分離許可は `REVIEW`）、ワークスペース外ファイルアクセス（`allow` は `WARN`）、無制限インターネットアクセス（`allow` は `REVIEW`）、ブラウザドメイン許可リスト、事前許可コマンドリスト。 |
| MCP Servers | グローバル（`config/mcp_config.json`）、ワークスペース（`.agents/mcp_config.json`）、プラグイン内の MCP 設定をスキャン。コマンド実行可能なランタイム（bash/python/node/curl/ssh 等）を `WARN` 検出、非暗号化 HTTP SSE エンドポイントを `WARN` 検出、機密環境変数をマスク。 |
| Lifecycle Hooks | グローバル、ワークスペース、プラグイン内の `hooks.json` をスキャン。全サポートイベント（`PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`）についてコマンドを抽出し、特権・破壊的コマンド等のリスクタグを評価。 |
| Plugins | `plugins/` ディレクトリ、`plugin.json` マニフェスト、`config.json` での有効/無効状態、および同梱機能（`skills`, `rules`, `hooks`, `mcp`）を検出。 |
| Customizations | `skills.json` および `plugins.json` の外部登録パス・継承関係（`inherits`, `entries`）を検出。 |
| Projects | 登録済みのプロジェクト一覧と、各プロジェクト固有の `.agents` カスタマイズ（スキル、ルール、hooks、MCP、プラグイン、プロジェクト設定）をスキャン。 |
| Trusted Folders | 自動実行が承認されている信頼済みフォルダ（`trustedFolders.json`）をスキャン。権限が拡張されているため `WARN`（警告）として報告。 |
| Skills & Rules | グローバル、ワークスペース、プラグイン内の `SKILL.md` やルールファイル（`GEMINI.md`, `AGENTS.md`, `.agents/rules/*.md`）を検出し、内部スクリプトファイルを点検。 |
| Sensitive Files | 認証情報（`oauth_creds.json`, `google_accounts.json`）や設定ファイルのパーミッションを検証。グループや一般ユーザーに広く読み取り権限が付与されている場合に `WARN` を検出。 |
| Retention | `history/`、`tmp/`、`antigravity-cli/`、セッション脳ログフォルダのファイル件数、容量、最新更新日時を算出。サイズ過大時に `REVIEW` を報告。 |
| Runtime | ローカル OS 上で実行中の antigravity / gemini 関連のプロセスを監視。 |

## クイックスタート

### Windows (PowerShell)

```powershell
# 監査を実行してターミナルに結果を出力
.\antigravity_audit.ps1

# 高い重大度の findings のみサマリ表示
.\antigravity_audit.ps1 --summary

# audit-viewer 取り込み用に JSON スナップショットを出力
.\antigravity_audit.ps1 --json --output snapshot.json

# 過去のスナップショットとの差分比較
.\antigravity_audit.ps1 --diff baseline.json

# HTML レポートの生成
.\antigravity_audit.ps1 --html report.html
```

### macOS (Zsh)

```bash
chmod +x ./antigravity_audit.sh

# 監査を実行
./antigravity_audit.sh

# JSON スナップショットを出力
./antigravity_audit.sh --json --output snapshot.json

# 過去のスナップショットとの差分比較
./antigravity_audit.sh --diff baseline.json

# HTML レポートの生成
./antigravity_audit.sh --html report.html
```

## オプション一覧

| オプション | 説明 |
|---|---|
| `--json` | 監査結果を JSON 形式で出力。 |
| `--html [FILE]` | HTML レポートファイルを生成（FILE 名省略時は自動命名）。 |
| `--summary` | 1行のサマリ情報と上位 Findings のみを表示。 |
| `--output FILE` | 出力内容を指定したファイルに直接書き込む。 |
| `--diff BASELINE.json` | ベースラインの JSON スナップショットと現在の状態を比較。 |
| `--diff-json` | 差分結果を JSON 形式で出力（`--diff` と併用）。 |
| `--fail-on warn\|review` | 指定された重大度が検出された場合に非ゼロの終了コードを返却（warn=2, review=1）。 |
| `--redact-paths` | ユーザー名やホームディレクトリパスなどの個人情報をマスクして出力。 |
| `--user USER` | ローカルマシン上の指定した別ユーザーを監査対象とする。 |
| `--all-users` | 構成データを持つすべてのユーザーを監査（要管理者権限）。 |
| `--antigravity-dir DIR` | `.gemini` 設定ディレクトリのパスを明示的に指定して監査。 |
| `-q, --quiet` | INFO レベルの Findings を非表示にする。 |

## 終了コード

- `0`: 監査成功、かつゲート条件に抵触なし。
- `1`: 引数エラー、または `--fail-on review` 指定時に `REVIEW` もしくは `WARN` が検出された。
- `2`: `--fail-on warn` 指定時に `WARN` が検出された。

## ライセンス

MIT
