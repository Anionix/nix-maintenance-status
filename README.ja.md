# nix-maintenance-status

[English](README.md) | [日本語](README.ja.md)

[![CI](https://github.com/Anionix/nix-maintenance-status/actions/workflows/ci.yml/badge.svg)](https://github.com/Anionix/nix-maintenance-status/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)](#プロジェクトの状態)

`nix-maintenance-status`は、Nixの自動メンテナンス設定と、それを実際に
実行するOSのジョブを結び付けて表示する、読み取り専用の診断ツールです。

宣言的なオプション、生成されたlaunchdジョブ、Nixコマンドは別々の層に
存在します。このツールは、それらを一つの機能と誤認しやすい問題を扱います。

> [!IMPORTANT]
> これは独立した個人プロジェクトです。Nix、NixOS、nix-darwinの公式
> プロジェクトではなく、それぞれのメンテナーとも提携していません。

## プロジェクトの状態

このリポジトリは、実験的な0.1系の実装です。CLI出力、RustライブラリAPI、
対応する証拠情報の取得元は、互換性の保証なしに変更される可能性があります。

| プラットフォーム | 設定層 | 実行層 | 状態 |
| --- | --- | --- | --- |
| macOS | nix-darwin | launchd | 実験的対応 |
| NixOS/Linux | NixOSモジュール | systemd | 計画中 |

## クイックスタート

現在のデフォルトブランチをNixから直接実行します。

```console
nix run github:Anionix/nix-maintenance-status
```

ローカルへ取得して実行する場合は次のとおりです。

```console
git clone https://github.com/Anionix/nix-maintenance-status.git
cd nix-maintenance-status
nix run .
```

出力例：

```text
Nix maintenance status

Garbage collection: enabled
Configuration: nix-darwin nix.gc.automatic (inferred)
Runtime job: org.nixos.nix-gc (loaded, idle)
Schedule: weekday 7 at 03:15
Command: /nix/store/...-nix/bin/nix-collect-garbage
Runs since load: 0
Last result: never run since the job was loaded
```

## 安全性とプライバシー

診断処理は意図的に読み取り専用です。実行時に行う処理は次の二つだけです。

- `launchctl print system/org.nixos.nix-gc`を実行する。
- `/Library/LaunchDaemons/org.nixos.nix-gc.plist`の存在を確認する。

GCの実行、Nix設定の編集、launchdの変更、テレメトリーの送信、ネットワーク
通信は行いません。`nix run github:...`は診断の開始前にソースと依存関係を
取得するため、ネットワークを使用します。

## 仕組み

最初に対応する経路は、三つの独立した層を通ります。

1. Nixが`nix-collect-garbage`を提供する。
2. nix-darwinが`nix.gc.automatic`モジュールオプションを提供する。
3. launchdが`org.nixos.nix-gc`をロードしてスケジュールする。

このツールはlaunchdから実行時の証拠を読み取り、それらの層を一つの状態
レポートにまとめます。利用者のnix-darwin設定を評価・変更することはありません。

## 証拠情報の分類

レポートでは、システムが直接証明する内容とツールの推定を区別します。

| 分類 | 意味 | 例 |
| --- | --- | --- |
| Observed | 実行中のジョブから直接読み取った情報 | ロード状態、コマンド、実行回数 |
| Inferred | 観測した証拠から推定した一般的な設定元 | 標準ジョブラベルから推定した`nix.gc.automatic` |
| Unknown | 調査対象のインターフェースが公開しない情報 | 正確な`.nix`ソースファイル |

launchdは生成されたジョブを公開しますが、元になったNixソースファイルや
モジュール代入は示しません。このため、設定の由来には常に`inferred`と表示します。

## 現在の制約

- macOSとnix-darwinの組み合わせだけに対応しています。
- スケジュールはlaunchdの数値カレンダー表現で表示します。
- 実行回数と終了結果は現在ロード中のジョブに関する情報で、永続履歴ではありません。
- `launchctl print`の人間向け出力を解析しています。
- 正確なオプション由来と次回の実行日時は取得できません。

## ロードマップ

- NixOS/systemdへの対応。
- 構造化JSON出力の追加。
- スケジュール表示の改善。
- 信頼できる情報源が存在する場合の、正確なモジュール由来の表示。

ロードマップは方向性を示すもので、提供時期を約束するものではありません。

## 開発

Nix開発環境に入り、品質ゲートを実行します。

```console
nix develop
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
nix flake check
```

現在、Rustクレートにサードパーティ依存関係はありません。

## コントリビューションとセキュリティ

小さく焦点の明確なIssueとPull Requestを歓迎します。貢献前に
[CONTRIBUTING.md](CONTRIBUTING.md)を確認してください。セキュリティ上の問題は、
[SECURITY.md](SECURITY.md)の手順に従って非公開で報告してください。

## ライセンス

[MIT License](LICENSE)で提供します。
