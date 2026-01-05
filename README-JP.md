<p align="center">
  <img src="./docs/deepflow-logo.png" alt="DeepFlow" width="300" />

  <p align="center">クラウド＆AIアプリケーションのためのインスタントオブザーバビリティ</p>
  <p align="center">ゼロコード、フルスタック、eBPF＆Wasm</p>
</p>
<p align="center">
    <a href="https://zenodo.org/badge/latestdoi/448599559"><img src="https://zenodo.org/badge/448599559.svg" alt="DOI"></a>
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/deepflowio/deepflow"> </a>
    <img alt="GitCode" src="https://gitcode.com/DeepFlow/deepflow/star/badge.svg"> </a>
    <img alt="docker pulls" src="https://img.shields.io/docker/pulls/deepflowce/deepflow-agent?color=green?label=docker pulls"> </a>
    <img alt="License" src="https://img.shields.io/github/license/deepflowio/deepflow?color=purple"> </a>
</p>

-------------

[English](./README.md) | [简体中文](./README-CN.md) | 日本語

# DeepFlowとは

DeepFlowオープンソースプロジェクトは、複雑なクラウドネイティブおよびAIアプリケーションに深い可観測性を提供することを目的としています。DeepFlowは、eBPFを使用してメトリック、分散トレーシング、リクエストログ、関数プロファイリングデータの**ゼロコード**データ収集を実装し、**SmartEncoding**と組み合わせて、すべての可観測性データの**フルスタック**相関と効率的なアクセスを実現しています。DeepFlowを使用すると、クラウドネイティブおよびAIアプリケーションは自動的に深い可観測性を備えることができ、開発者がコードに継続的にインストルメントを挿入するという重い負担を取り除き、DevOps/SREチームにコードからインフラストラクチャまでの監視および診断機能を提供します。

# 主な特徴

- **任意の**サービスの**全景図**：eBPFの**ゼロコード**を利用して、あらゆる言語で開発されたアプリケーションサービス、AIサービス、インフラストラクチャサービスの生産環境の全景図を描画します。標準プロトコルの解析機能を内蔵し、Wasmプラグイン機構を提供して、任意のプライベートプロトコルを拡張解析します。アプリケーションとインフラストラクチャの**フルスタック**ゴールデンシグナルを**ゼロコード**で計算し、パフォーマンスのボトルネックを迅速に特定します。
- **任意の**リクエストの**分散トレーシング**：eBPFの**ゼロコード**分散トレーシング機能は、あらゆる言語のアプリケーションをサポートし、ゲートウェイ、サービスメッシュ、データベース、メッセージキュー、DNS、NICなど、あらゆる種類のインフラストラクチャを完全にカバーし、トレーシングの盲点を残しません。**フルスタック**、各Spanに関連するネットワークパフォーマンス指標とファイル読み取り/書き込みイベントを自動的に収集します。これにより、分散トレーシングはゼロインストルメントの新時代に入ります。
- **任意の**関数の**継続的なパフォーマンスプロファイリング**：1%未満のオーバーヘッドで生産環境のプロセスのパフォーマンスプロファイリングデータを**ゼロコード**で収集し、OnCPU/OffCPU/GPU/Memory/Networkの関数呼び出しスタックの火焰図を描画し、ビジネス関数、フレームワーク関数、ランタイム関数、共有ライブラリ関数、カーネル関数、CUDA関数の**フルスタック**パフォーマンスのボトルネックを迅速に特定し、それらを分散トレーシングデータに自動的に関連付けます。
- **人気のある可観測性技術スタックとのシームレスな統合**：Prometheus、OpenTelemetry、SkyWalking、Pyroscopeのストレージバックエンドとして機能することができます。また、**SQL、PromQL、OTLP**などのデータインターフェースを提供して、人気のある技術スタックのデータソースとして機能します。すべての観測信号にクラウドリソース、K8sコンテナリソース、K8s Label/Annotation、CMDBのビジネス属性などの統一タグを自動的に注入し、データの孤立を解消します。
- **ClickHouseの10倍のストレージ性能**：**SmartEncoding**機構を使用して、すべての観測データに標準化された、事前エンコードされたメタタグを注入し、ClickHouseのStringまたはLowCard方式と比較してストレージオーバーヘッドを10倍削減します。カスタムタグと観測データは別々に保存されるため、無制限の次元と基数のタグを安心して注入でき、**BigTable**のような快適なクエリ体験を得ることができます。

# ドキュメント

詳細については、[ドキュメントサイト](https://deepflow.io/docs/?from=github)をご覧ください。

# クイックスタート

DeepFlowには3つのバージョンがあります：
- DeepFlow Community：開発者向けのDeepFlowコミュニティ版
- DeepFlow Enterprise：組織向けのDeepFlowエンタープライズ版、チーム協力の問題を解決
- DeepFlow Cloud：DeepFlowのSaaSサービス、現在ベータテスト中

DeepFlowコミュニティ版は、エンタープライズ版のコアコンポーネントで構成されています。オープンソースを通じて、私たちは観測をより自動化し、世界中の開発者がより自由になることを願っています。

## DeepFlow Communityのデプロイ

[ドキュメント](https://deepflow.io/docs/ce-install/all-in-one/?from=github)に従って、DeepFlow Communityをデプロイしてください。

また、完全な[DeepFlow Community Demo](https://ce-demo.deepflow.yunshan.net/?from=github)も構築していますので、ぜひ体験してみてください。ログインアカウント/パスワード：deepflow / deepflow-2026

## DeepFlow Enterpriseを体験する

[DeepFlow Enterprise Demo](https://deepflow.io/)にアクセスしてください。現在、中国語のみをサポートしています。

# DeepFlowのソースコードからのコンパイル

- [deepflow-agentのコンパイル](./agent/build.md)

# ソフトウェアアーキテクチャ

DeepFlow Community版は、AgentとServerの2つのプロセスで構成されています。各K8sコンテナノード、従来のサーバー、またはクラウドサーバーには、そのサーバー上のすべてのアプリケーションプロセスのデータ収集を担当するAgentが1つ実行されます。ServerはK8sクラスター内で実行され、Agent管理、タグ注入、データ書き込み、データクエリサービスを提供します。

![DeepFlow ソフトウェアアーキテクチャ](./docs/deepflow-architecture.png)

# マイルストーン

こちらは、[将来の機能計画](https://deepflow.io/docs/about/milestone/?from=github)です。IssueやPull Requestを歓迎します。

# お問い合わせ

- Discord：[こちら](https://discord.gg/QJ7Dyj4wWM)をクリックして、Discordチャンネルに参加してください。
- Twitter：[DeepFlow](https://twitter.com/deepflowio)
- WeChatグループ：
<img src=./docs/wechat-group-keeper.png width=30% />

# 謝辞

- [eBPF](https://ebpf.io/)に感謝します。革命的なLinuxカーネル技術です。
- [OpenTelemetry](https://opentelemetry.io/)に感謝します。アプリケーションの可観測性データを収集するためのベンダーニュートラルなAPIを提供しています。

# 名誉

- DeepFlowの論文[Network-Centric Distributed Tracing with DeepFlow: Troubleshooting Your Microservices in Zero Code](https://dl.acm.org/doi/10.1145/3603269.3604823)が、国際トップ会議ACM SIGCOMM 2023に採択されました。
- DeepFlowは<a href="https://landscape.cncf.io/?selected=deep-flow">CNCF CLOUD NATIVE Landscape</a>に追加されました。
- DeepFlowは<a href="https://landscape.cncf.io/?selected=deep-flow&group=cnai&item=cnai--model-llm-observability--deepflow">CNCF CNAI (Cloud-Native AI) Landscape</a>に追加されました。
- DeepFlowは<a href="https://ebpf.io/applications#deepflow">eBPF Project Landscape</a>に追加されました。
