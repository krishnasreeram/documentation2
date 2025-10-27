# Azure → AWS Multi‑Tenant DB Migration — Research Notes & Recommended Approaches

> Names have been removed. Each item includes one or more recommended approaches backed by AWS references (see **References**).

---

## 1) Tenant‑Level Database Separation
**Summary:** Each tenant should have strong isolation to meet compliance and reduce blast radius. RDS for SQL Server has per‑instance database count constraints that can limit growth.

**Recommended approaches**
- **Dedicated database per tenant on RDS for SQL Server (initial phase).**
  - Pros: clear isolation, simpler per‑tenant lifecycle (backup/restore, schema versioning).
  - Cons: hard ceiling on databases per instance; plan horizontal scale from day one (see §2).  
- **Move to Aurora (PostgreSQL‑compatible) when tenant count or elasticity needs exceed RDS SQL Server.**
  - Use “database‑per‑tenant” or “schema‑per‑tenant” patterns; favor DB‑per‑tenant for strict isolation.  
- **Tiered model:** small tenants consolidated on shared instances; high‑volume tenants get dedicated instances/clusters.

---

## 2) AWS RDS Limits & Horizontal Scale
**Summary:** RDS for SQL Server imposes a maximum number of databases per DB instance (varies by instance class/HA mode; commonly referenced planning figure is ~100). This constrains pure “one instance for many DBs” designs.

**Recommended approaches**
- **Shard tenants across multiple RDS SQL Server instances.**
  - Maintain a tenant routing catalog (lookup service or config table) to resolve `tenant → instance/database`.
- **Plan an on‑ramp to Aurora.**
  - Aurora removes the per‑instance DB count constraint and offers elastic compute/storage options (see §7).

**Notes:** Always validate the current documented limits for your chosen instance class and HA mode during sizing.

---

## 3) Phased Migration Strategy
**Summary:** Start with lift‑and‑shift for speed, then modernize for scale/cost.

**Recommended approaches**
- **Phase 1 (Lift‑and‑Shift):** RDS for SQL Server, Multi‑AZ for HA, storage autoscaling, CloudWatch alarms.
- **Phase 2 (Replatform):** Use AWS SCT/DMS to move to Aurora PostgreSQL where elasticity, IAM auth, and pooling are needed.
- **Phase 3 (Optimize):** Adopt Aurora Serverless v2 for elastic compute; tune connection pooling and failover posture.

---

## 4) Application Impact of Engine Choice
**Summary:** Changing engines affects T‑SQL, data types, and stored procs.

**Recommended approaches**
- **Abstract data access.** Use ORMs or internal data libraries to reduce engine‑specific SQL.
- **Use AWS Schema Conversion Tool (SCT).** Convert schema and procs; generate assessment reports and shim code where needed.
- **Stage & test.** Full integration tests in a staging environment before cutover.

---

## 5) Security, Compliance & Authentication
**Summary:** IAM DB authentication isn’t available for RDS SQL Server; it is available for MySQL/PostgreSQL (incl. Aurora).

**Recommended approaches**
- **Initial phase:** SQL authentication on RDS SQL Server with Secrets Manager rotation; TLS enforced in‑transit; KMS at‑rest.
- **Future phase:** Migrate to Aurora PostgreSQL and enable **IAM DB authentication** to remove long‑lived DB passwords.
- **Network controls:** Private subnets, security groups, and restricted SG rules; audit at SQL layer.

---

## 6) Backup, Restore & DR Compliance
**Summary:** Automated backups and PITR are mandatory; verify restores regularly.

**Recommended approaches**
- **Automated backups + PITR** on all prod instances; quarterly restore drills to validate RTO/RPO.
- **Cross‑Region snapshots** for DR; document failover runbooks and recovery checkpoints.
- **Per‑tenant recovery:** With DB‑per‑tenant, use DB‑level snapshot/restore to recover individual tenants without broad impact.

---

## 7) Scalability & Resource Management
**Summary:** RDS SQL Server does not autoscale compute; storage can autoscale.

**Recommended approaches**
- **Storage autoscaling** to avoid space exhaustion.
- **Operational playbooks** for manual instance scale‑up/down during maintenance windows; use CW alarms to trigger runbooks.
- **Aurora Serverless v2** for elastic compute (including ability to scale down aggressively; latest supports scale‑to‑0 where appropriate).

---

## 8) Handling Highly Variable Tenant Workloads
**Summary:** Tenants range from very small to very large (e.g., 100 to 150k devices).

**Recommended approaches**
- **Tiering:** Place “small” tenants on shared clusters; isolate “large/noisy” tenants.
- **Read scaling:** Use Aurora read replicas; route read‑heavy traffic appropriately.
- **QoS/Throttle:** Implement request shaping in the app tier to protect shared resources.

---

## 9) Schema Management & Migrations
**Summary:** Current practice uses DACPAC for in‑place upgrades with short maintenance—no strict zero‑downtime.

**Recommended approaches**
- **Keep DACPAC** for SQL Server during Phase 1; standardize versioning and pre‑checks.
- **Evaluate Liquibase/Flyway** for engine‑agnostic migrations and drift detection; run via CI/CD.
- **Blue/green for near‑zero downtime (Aurora):** clone + cutover or use writer/reader role swap after applying migrations.

---

## 10) Downtime Strategy for Upgrades
**Summary:** Aim to minimize downtime; true zero‑downtime requires architectural support.

**Recommended approaches**
- **Maintenance windows** with tenant notice SLAs on RDS SQL Server.
- **Aurora + blue/green** or physical cluster clone to reduce interruption.
- **Connection management:** Consider **RDS Proxy** where compatible to smooth failovers and reduce cold‑start spikes.

---

## 11) Rollback & Recovery for Failed Upgrades
**Summary:** Current policy restores only to previous version using pre‑upgrade backups.

**Recommended approaches**
- **Pre‑upgrade snapshot per tenant DB** and attached change logs; automate rollback to N‑1.
- **Guardrails:** Block rollout to remaining tenants on first failure; require manual override after diagnosis.
- **Data‑aware migrations:** Prefer additive changes; avoid destructive DDL where possible.

---

## 12) Tenant Provisioning & Lifecycle Management
**Summary:** Existing tool creates DBs, Kafka topics, and service accounts; minor AWS SQL command differences expected.

**Recommended approaches**
- **Standardize provisioning** via CloudFormation or CDK; orchestrate with Step Functions (idempotent steps).
- **Split concerns:** App user creation and perms handled by a dedicated pipeline using Liquibase/Flyway changeSets.
- **Golden template DB** kept current; clone for new tenants to reduce drift and time‑to‑value.

---

## 13) Monitoring, Alerting & Performance
**Summary:** Datadog + CloudWatch provide metrics, logs, and APM.

**Recommended approaches**
- **CloudWatch first for alarms** (cost‑efficient); forward selected logs/metrics to Datadog for dashboards and deep analysis.
- **SQL Server Query Store** for plan/regression analysis; integrate surface metrics into Datadog.
- **SLOs & error budgets** drive alerts; auto‑create tickets on burn‑rate breaches.

---

## 14) Security, Auditing & Access Control
**Summary:** Need SQL auditing and network isolation equivalent to Azure posture.

**Recommended approaches**
- **Enable SQL auditing** (RDS feature) and stream to CloudWatch; constrain access to logs.
- **Network isolation:** VPC, private subnets, SG least‑privilege; no public endpoints.
- **Periodic reviews:** IAM access analyzer; quarterly DB role and secrets rotation audits.

---

## 15) Cost Optimization & Efficiency
**Summary:** Control cost while scaling.

**Recommended approaches**
- **Right‑size** with Compute Optimizer + CW trends; cap instance counts via tenant sharding plans.
- **RDS Reserved Instances/Savings Plans** for steady prod loads; on‑demand for bursty lower envs.
- **Consolidation with guardrails:** Co‑locate small tenants but cap per‑instance DBs well below limits to maintain headroom.

---

## 16) Documentation, Change Tracking & Traceability
**Summary:** Strong documentation and version control are required for audits and ops excellence.

**Recommended approaches**
- **Git‑backed change control** for schema and infra (IaC) with PR reviews.
- **Runbooks & templates** (Confluence/MD) for migrations, rollbacks, DR tests, and tenant ops.
- **Automated release notes** generated from migration pipelines (include affected tenants, timing, risk level).

---

## 17) Customer‑Managed Encryption Keys (Future)
**Summary:** Customers may require CMK ownership/rotation.

**Recommended approaches**
- **Use AWS KMS CMKs** per tenant or per tier; define key policies that scope access to your service roles only.
- **Secrets Manager** for DB creds with scheduled rotation; integrate into app startup and migration pipelines.
- **Document shared‑responsibility model** for key lifecycle, rotation intervals, and incident handling.

---

## 18) Follow‑Up Actions (Next 2–4 Weeks)
1. Finalize target engines per tier (RDS SQL Server vs. Aurora PostgreSQL) and document scaling thresholds.
2. Produce tenant routing specification and catalog schema; implement POC.
3. Write migration runbooks: pre‑checks, snapshot/backup, rollout gates, rollback.
4. Stand up reference monitoring dashboards (CW + Datadog) and SLOs.
5. Security review: confirm initial SQL auth posture; draft IAM DB auth plan for Aurora phase.
6. Cost plan: RI/SP coverage and per‑tenant cost model.

---

## References
1. **RDS SQL Server limits & constraints** — Amazon RDS User Guide. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_SQLServer.html
2. **RDS general limits** — Amazon RDS Limits. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_Limits.html
3. **IAM DB Authentication (supported engines)** — RDS Docs. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RDS_Fea_Regions_DB-eng.Feature.IamDatabaseAuthentication.html
4. **IAM DB Authentication (how‑to)** — RDS Docs. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
5. **RDS storage autoscaling** — RDS Docs. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIOPS.Autoscaling.html
6. **Aurora Serverless v2** — RDS Aurora Docs. https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.how-it-works.html
7. **Aurora Serverless v2 capacity configuration** — RDS Aurora Docs. https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.setting-capacity.html
8. **Aurora Serverless v2 scale‑to‑0 (update)** — AWS Database Blog. https://aws.amazon.com/blogs/database/introducing-scaling-to-0-capacity-with-amazon-aurora-serverless-v2/
9. **RDS Proxy (engines & support)** — AWS “What’s New” + Docs. https://aws.amazon.com/about-aws/whats-new/2022/09/amazon-rds-proxy-rds-sql-server/ , https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html
10. **AWS SCT** — AWS Docs. https://docs.aws.amazon.com/SchemaConversionTool/latest/userguide/CHAP_Welcome.html
11. **Query Store on RDS SQL Server** — AWS Database Blog. https://aws.amazon.com/blogs/database/capture-and-tune-resource-utilization-metrics-for-amazon-rds-for-sql-server/
12. **SaaS relational DB scaling patterns** — AWS Database Blog. https://aws.amazon.com/blogs/database/scale-your-relational-database-for-saas-part-1-common-scaling-patterns/
