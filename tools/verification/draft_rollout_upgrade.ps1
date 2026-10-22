param(
    [string]$Container = 'mk-acceptance-pg-20261021',
    [string]$TemplateDatabase = 'mk_kernel_test',
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$taskLabel = docker inspect --format '{{index .Config.Labels "codex.task"}}' $Container
if ($LASTEXITCODE -ne 0 -or $taskLabel -ne 'mk-87-rows') { throw 'Only the task-owned disposable Postgres container is allowed.' }
if ($TemplateDatabase -notmatch '^mk_[a-z0-9_]+$') { throw 'Invalid template database.' }
$taskVersion = docker exec $Container psql -U postgres -d $TemplateDatabase -At -c 'SELECT max(version) FROM _sqlx_migrations'
if ($LASTEXITCODE -ne 0 -or $taskVersion -ne '12') { throw 'This upgrade scenario requires the retained migration-12 test database.' }
$taskDatabase = 'mk_h2_upgrade_' + [Guid]::NewGuid().ToString('N')
if ($taskDatabase -notmatch '^mk_h2_upgrade_[a-f0-9]{32}$') { throw 'Invalid disposable database identity.' }
$taskCreated = $false
function Invoke-TaskSql([string]$Sql) {
    $taskResult = docker exec $Container psql -U postgres -d $taskDatabase -v ON_ERROR_STOP=1 -At -c $Sql
    if ($LASTEXITCODE -ne 0) { throw 'Upgrade SQL failed.' }
    return $taskResult
}
function Apply-TaskMigration([string]$Name) {
    Get-Content -LiteralPath (Join-Path $taskRoot "migrations/kernel/$Name") -Raw |
        docker exec -i $Container psql -U postgres -d $taskDatabase -v ON_ERROR_STOP=1 -q
    if ($LASTEXITCODE -ne 0) { throw "Migration failed: $Name" }
}
try {
    docker exec $Container psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE $taskDatabase TEMPLATE $TemplateDatabase"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create isolated upgrade database.' }
    $taskCreated = $true
    Apply-TaskMigration '0013_inbound_probes.sql'
    Apply-TaskMigration '0014_draft_invalidation.sql'
    # Simulate an old intake binary during the migration window. A real action
    # row is inserted after backfill but before the version-15 insert trigger.
    $taskDraft = [Guid]::NewGuid().ToString()
    $taskAction = [Guid]::NewGuid().ToString()
    $taskSql = @"
WITH seed AS (
 SELECT a, convert_to((convert_from(canonical_request,'UTF8')::jsonb || jsonb_build_object(
   'action_id','$taskAction','evidence',jsonb_build_array(jsonb_build_object(
     'type','document','id','draft:$taskDraft','digest','sha256:'||repeat('a',64)))))::text,'UTF8') AS canonical
 FROM kernel.actions a LIMIT 1
)
INSERT INTO kernel.actions SELECT (jsonb_populate_record(NULL::kernel.actions,to_jsonb(a) || jsonb_build_object(
 'action_id','$taskAction','canonical_request',canonical,'action_digest','sha256:'||encode(sha256(canonical),'hex'),
 'idempotency_key','upgrade-$taskAction','state','draft','attempt',0,'error_code',NULL))).* FROM seed
"@
    Invoke-TaskSql $taskSql | Out-Null
    $taskMissingBefore = Invoke-TaskSql "SELECT count(*) FROM kernel.actions a LEFT JOIN kernel.draft_action_refs r USING(tenant_id,action_id) WHERE a.action_id='$taskAction' AND r.action_id IS NULL"
    if ($taskMissingBefore -ne '1') { throw 'The rollout-gap negative control was not reproduced.' }
    Apply-TaskMigration '0015_draft_fence_insert_guard.sql'
    Apply-TaskMigration '0016_draft_rollout_backfill.sql'
    $taskRecovered = Invoke-TaskSql "SELECT count(*) FROM kernel.draft_action_refs WHERE action_id='$taskAction' AND draft_id='$taskDraft'"
    if ($taskRecovered -ne '1') { throw 'The rollout-gap action was not recovered.' }
    Apply-TaskMigration '0016_draft_rollout_backfill.sql'
    $taskAfterRepeat = Invoke-TaskSql "SELECT count(*) FROM kernel.draft_action_refs WHERE action_id='$taskAction'"
    if ($taskAfterRepeat -ne '1') { throw 'Repeat backfill duplicated a reference.' }
    $taskReport = [ordered]@{ environment='task-owned real PostgreSQL 16; isolated database cloned from migration 12';
        rollout_gap_reproduced=[int]$taskMissingBefore; recovered_action_refs=[int]$taskRecovered;
        refs_after_repeat_backfill=[int]$taskAfterRepeat; result='Worked'; disposable_database=$taskDatabase }
} finally {
    if ($taskCreated) {
        docker exec $Container psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q -c "DROP DATABASE $taskDatabase"
        if ($LASTEXITCODE -ne 0) { throw "Cleanup failed; task-owned database retained: $taskDatabase" }
    }
}
$taskReport['disposable_database_removed'] = $true
$taskReport | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding utf8
$taskReport | ConvertTo-Json
