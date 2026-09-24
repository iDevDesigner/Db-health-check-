/* ============================================================================
   Monthly Partitioned Archive for RequestLogs  (SQL Server / T-SQL)
   ----------------------------------------------------------------------------
   What it does:
     1) Creates a monthly RANGE-RIGHT partitioned copy of RequestLogs in the
        ARCHIVE database (same structure, partition-aligned clustered index).
     2) Audit table  : dbo.ArchiveCopyLog   (row counts + error details/run)
        Queue table  : dbo.ArchiveCopyQueue (month-level work items)
     3) Stored procs :
          dbo.usp_ArchiveRequestLogs_Monthly  - copies ONE month, minimal log,
                                                idempotent (safe re-run),
                                                optional batched source delete
          dbo.usp_ArchiveCopyWorker           - claims ONE queued month (for
                                                parallel Agent jobs)
          dbo.usp_ArchiveRequestLogs_Dispatch - queues a month range and starts
                                                N parallel Agent jobs
     4) Minimal logging: archive DB in BULK_LOGGED recovery + TABLOCK +
        per-month transactions. Errors and row counts land in ArchiveCopyLog.
   ----------------------------------------------------------------------------
   ASSUMPTIONS / EDIT BEFORE RUNNING:
     - Archive DB and Production DB are on the SAME instance (3-part names).
       (Cross-server/linked-server copy cannot be minimally logged - slow.)
     - Edit CONFIG below: boundary range, data file path, source DB/table.
     - Run SECTION 1..4 connected to the ARCHIVE database.
     - Run SECTION 5 (Agent job) connected to msdb.
   ============================================================================ */
SET NOCOUNT ON;

/* ============================================================================
   SECTION 0 - CONFIG
   ============================================================================ */
DECLARE @FirstBoundary date = '20250101';   -- leftmost partition boundary
DECLARE @LastBoundary  date = '20270101';   -- rightmost boundary (last month)
DECLARE @DataPath      nvarchar(260) = N'D:\SQLData\';  -- .mdf path for FG files

/* ============================================================================
   SECTION 1 - Filegroups, partition function & scheme (run once)
   ============================================================================ */
DECLARE @d date = @FirstBoundary;
DECLARE @sql nvarchar(max) = N'';

-- 1a) One filegroup + one file per month
WHILE @d <= @LastBoundary
BEGIN
    DECLARE @fg sysname = N'FG_' + FORMAT(@d, 'yyyyMM');
    SET @sql += N'
IF NOT EXISTS (SELECT 1 FROM sys.filegroups WHERE name = N''' + @fg + N''')
    ALTER DATABASE ' + QUOTENAME(DB_NAME()) + N' ADD FILEGROUP ' + QUOTENAME(@fg) + N';
IF NOT EXISTS (SELECT 1 FROM sys.database_files WHERE name = N''' + @fg + N'_data'')
    ALTER DATABASE ' + QUOTENAME(DB_NAME()) + N' ADD FILE
    (NAME = N''' + @fg + N'_data'', FILENAME = N''' + @DataPath + @fg + N'.ndf'', SIZE = 512MB, FILEGROWTH = 256MB)
    TO FILEGROUP ' + QUOTENAME(@fg) + N';' + CHAR(10);
    SET @d = DATEADD(month, 1, @d);
END
EXEC sys.sp_executesql @sql;

-- 1b) Partition function: RANGE RIGHT => boundary value belongs to the RIGHT
--     partition, so '2025-02-01' boundary = February's partition.
SET @sql = N'';
SET @d = DATEADD(month, 1, @FirstBoundary);
WHILE @d <= @LastBoundary
BEGIN
    SET @sql += CASE WHEN @sql = N'' THEN N'' ELSE N',' END
              + N'''' + CONVERT(char(8), @d, 112) + N'''';
    SET @d = DATEADD(month, 1, @d);
END
SET @sql = N'
IF EXISTS (SELECT 1 FROM sys.partition_functions WHERE name = N''pf_RequestLogs_Monthly'')
    DROP PARTITION SCHEME ps_RequestLogs_Monthly;  -- drop scheme first if exists
IF EXISTS (SELECT 1 FROM sys.partition_functions WHERE name = N''pf_RequestLogs_Monthly'')
    DROP PARTITION FUNCTION pf_RequestLogs_Monthly;
CREATE PARTITION FUNCTION pf_RequestLogs_Monthly (datetime) AS RANGE RIGHT FOR VALUES (' + @sql + N');';

-- 1c) Partition scheme: catch-all -> first FG, each boundary month -> its FG,
--     tail -> last FG. Generated to match the function exactly.
DECLARE @map nvarchar(max) = N'', @firstFG sysname = N'FG_' + FORMAT(@FirstBoundary, 'yyyyMM');
SET @map = QUOTENAME(@firstFG) + N',';                       -- catch-all partition
SET @d = DATEADD(month, 1, @FirstBoundary);
WHILE @d <= @LastBoundary
BEGIN
    SET @map += QUOTENAME(N'FG_' + FORMAT(@d, 'yyyyMM')) + N',';
    SET @d = DATEADD(month, 1, @d);
END
SET @map += QUOTENAME(N'FG_' + FORMAT(@LastBoundary, 'yyyyMM'));

SET @sql += N'
CREATE PARTITION SCHEME ps_RequestLogs_Monthly AS PARTITION pf_RequestLogs_Monthly ALL TO (' + @map + N');';
EXEC sys.sp_executesql @sql;

/* ============================================================================
   SECTION 2 - Partitioned archive table (same structure as production)
   NOTE: a partitioned table's clustered index MUST contain the partitioning
   column, so the PK on Id becomes NONCLUSTERED and the clustered index is
   (Timestamp, Id) - aligned with the scheme.
   ============================================================================ */
IF OBJECT_ID('dbo.RequestLogs', 'U') IS NOT NULL DROP TABLE dbo.RequestLogs;
GO
CREATE TABLE dbo.RequestLogs
(
    Id             bigint        NOT NULL IDENTITY(1,1),
    [Timestamp]    datetime      NOT NULL,
    DeviceID       nvarchar(max)     NULL,
    Appcode        nvarchar(max)     NULL,
    UserID         nvarchar(128)     NULL,
    RequestObject  nvarchar(max)     NULL,
    Url            nvarchar(max)     NULL,
    CONSTRAINT PK_RequestLogs PRIMARY KEY NONCLUSTERED (Id)
        ON [PRIMARY]
) ON ps_RequestLogs_Monthly ([Timestamp]);
GO
CREATE CLUSTERED INDEX CIX_RequestLogs_Ts_Id
    ON dbo.RequestLogs ([Timestamp], Id)
    ON ps_RequestLogs_Monthly ([Timestamp]);
GO
-- FK to AspNetUsers intentionally omitted in the archive (target table may not
-- exist there); add it later with NOCHECK if you really need it.

/* ============================================================================
   SECTION 3 - Audit + queue tables
   ============================================================================ */
IF OBJECT_ID('dbo.ArchiveCopyLog', 'U') IS NULL
CREATE TABLE dbo.ArchiveCopyLog
(
    LogId          bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_ArchiveCopyLog PRIMARY KEY,
    RunId          uniqueidentifier     NOT NULL,
    SourceTable    nvarchar(300)        NOT NULL,
    TargetTable    nvarchar(300)        NOT NULL,
    MonthStart     date                 NOT NULL,
    RowsSource     bigint               NULL,
    RowsCopied     bigint               NULL,
    RowsDeleted    bigint               NULL,
    Status         varchar(10)          NOT NULL,   -- RUNNING / SUCCESS / FAILED
    ErrorNumber    int                  NULL,
    ErrorLine      int                  NULL,
    ErrorProcedure sysname              NULL,
    ErrorMessage   nvarchar(4000)       NULL,
    StartedAt      datetime2            NOT NULL,
    FinishedAt     datetime2            NULL,
    DurationSec    AS (DATEDIFF(second, StartedAt, FinishedAt))
);
CREATE INDEX IX_ArchiveCopyLog_Month ON dbo.ArchiveCopyLog (MonthStart, Status);
GO

IF OBJECT_ID('dbo.ArchiveCopyQueue', 'U') IS NULL
CREATE TABLE dbo.ArchiveCopyQueue
(
    MonthStart date           NOT NULL CONSTRAINT PK_ArchiveCopyQueue PRIMARY KEY,
    Status     varchar(10)    NOT NULL CONSTRAINT DF_ArchiveCopyQueue_Status DEFAULT ('QUEUED'),
    Attempts   tinyint        NOT NULL CONSTRAINT DF_ArchiveCopyQueue_Attempts DEFAULT (0),
    ClaimedAt  datetime2      NULL,
    DoneAt     datetime2      NULL
);
GO

/* ============================================================================
   SECTION 4 - Stored procedures
   ============================================================================ */

/* ---- 4a) Copy ONE month, minimal logging, idempotent, logged ------------ */
CREATE OR ALTER PROCEDURE dbo.usp_ArchiveRequestLogs_Monthly
    @MonthStart      date,                       -- any date inside the month
    @SourceDB        sysname = N'ProductionDB',  -- source database
    @SourceTable     nvarchar(300) = N'dbo.RequestLogs',
    @DeleteSource    bit = 0,                    -- 1 = delete copied month from source
    @DeleteBatchSize int = 50000,
    @MaxDOP          int = 4
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @RunId     uniqueidentifier = NEWID();
    DECLARE @MonthEnd  date = DATEADD(month, 1, DATEFROMPARTS(YEAR(@MonthStart), MONTH(@MonthStart), 1));
    SET @MonthStart = DATEFROMPARTS(YEAR(@MonthStart), MONTH(@MonthStart), 1);

    DECLARE @copied bigint = 0, @srcCnt bigint = 0, @deleted bigint = 0,
            @p int, @fg sysname, @sql nvarchar(max);

    INSERT dbo.ArchiveCopyLog (RunId, SourceTable, TargetTable, MonthStart, Status, StartedAt)
    VALUES (@RunId, QUOTENAME(@SourceDB) + N'.' + @SourceTable, N'dbo.RequestLogs',
            @MonthStart, 'RUNNING', SYSUTCDATETIME());

    BEGIN TRY
        BEGIN TRANSACTION;

        /* 1) Idempotent re-run: if the target month already has rows, SWITCH it
              out to an empty staging table on the same filegroup and drop it.
              SWITCH = metadata-only, DROP = instant. Zero heavy logging. */
        IF EXISTS (SELECT 1 FROM dbo.RequestLogs
                   WHERE [Timestamp] >= @MonthStart AND [Timestamp] < @MonthEnd)
        BEGIN
            SET @p = $PARTITION.pf_RequestLogs_Monthly(@MonthStart);
            SELECT @fg = fg.name
            FROM sys.partition_schemes ps
            JOIN sys.destination_data_spaces dds
              ON dds.partition_scheme_id = ps.data_space_id AND dds.destination_id = @p
            JOIN sys.filegroups fg ON fg.data_space_id = dds.data_space_id
            WHERE ps.name = N'ps_RequestLogs_Monthly';

            SET @sql = N'
CREATE TABLE dbo.swStage (
    Id bigint NOT NULL, [Timestamp] datetime NOT NULL,
    DeviceID nvarchar(max) NULL, Appcode nvarchar(max) NULL,
    UserID nvarchar(128) NULL, RequestObject nvarchar(max) NULL, Url nvarchar(max) NULL,
    CONSTRAINT PK_swStage PRIMARY KEY NONCLUSTERED (Id));
CREATE CLUSTERED INDEX CIX_swStage ON dbo.swStage ([Timestamp], Id)
    ON ' + QUOTENAME(@fg) + N';
ALTER TABLE dbo.RequestLogs SWITCH PARTITION ' + CAST(@p AS nvarchar(10)) + N' TO dbo.swStage;
DROP TABLE dbo.swStage;';
            EXEC sys.sp_executesql @sql;
        END

        /* 2) Source row count for audit */
        SET @sql = N'SELECT @c = COUNT_BIG(*) FROM ' + QUOTENAME(@SourceDB) + N'.'
                 + @SourceTable + N' WITH (NOLOCK)
                   WHERE [Timestamp] >= @ms AND [Timestamp] < @me;';
        EXEC sys.sp_executesql @sql, N'@ms date, @me date, @c bigint OUTPUT',
                               @ms = @MonthStart, @me = @MonthEnd, @c = @srcCnt OUTPUT;

        /* 3) The copy. TABLOCK enables minimal logging (empty partition +
              BULK_LOGGED/SIMPLE recovery). MAXDOP gives intra-statement
              parallelism. One month per transaction = short log reuse. */
        SET @sql = N'
SET IDENTITY_INSERT dbo.RequestLogs ON;
INSERT dbo.RequestLogs WITH (TABLOCK)
       (Id, [Timestamp], DeviceID, Appcode, UserID, RequestObject, Url)
SELECT Id, [Timestamp], DeviceID, Appcode, UserID, RequestObject, Url
FROM ' + QUOTENAME(@SourceDB) + N'.' + @SourceTable + N' WITH (TABLOCK)
WHERE [Timestamp] >= @ms AND [Timestamp] < @me
OPTION (MAXDOP ' + CAST(@MaxDOP AS nvarchar(3)) + N');
SET @c = @@ROWCOUNT;
SET IDENTITY_INSERT dbo.RequestLogs OFF;';
        EXEC sys.sp_executesql @sql, N'@ms date, @me date, @c bigint OUTPUT',
                               @ms = @MonthStart, @me = @MonthEnd, @c = @copied OUTPUT;

        IF @copied <> @srcCnt
            THROW 50001, 'Row count mismatch between source and archive - transaction rolled back.', 1;

        /* 4) Optional: remove the archived month from production in small
              batches to keep the production log small and reusable. */
        IF @DeleteSource = 1 AND @copied > 0
        BEGIN
            DECLARE @b bigint;
            SET @sql = N'DELETE TOP (' + CAST(@DeleteBatchSize AS nvarchar(10)) + N')
                        FROM ' + QUOTENAME(@SourceDB) + N'.' + @SourceTable + N'
                        WHERE [Timestamp] >= @ms AND [Timestamp] < @me;';
            WHILE 1 = 1
            BEGIN
                EXEC sys.sp_executesql @sql, N'@ms date, @me date', @ms = @MonthStart, @me = @MonthEnd;
                SET @b = @@ROWCOUNT;
                SET @deleted += @b;
                IF @b = 0 BREAK;
            END
        END

        COMMIT TRANSACTION;

        UPDATE dbo.ArchiveCopyLog
        SET RowsSource = @srcCnt, RowsCopied = @copied, RowsDeleted = @deleted,
            Status = 'SUCCESS', FinishedAt = SYSUTCDATETIME()
        WHERE RunId = @RunId;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        UPDATE dbo.ArchiveCopyLog
        SET Status = 'FAILED', FinishedAt = SYSUTCDATETIME(),
            ErrorNumber = ERROR_NUMBER(), ErrorLine = ERROR_LINE(),
            ErrorProcedure = ERROR_PROCEDURE(), ErrorMessage = ERROR_MESSAGE()
        WHERE RunId = @RunId;
        THROW;   -- re-raise so the caller/job also sees the failure
    END CATCH
END
GO

/* ---- 4b) Worker: claims ONE queued month (safe under concurrency) ------- */
CREATE OR ALTER PROCEDURE dbo.usp_ArchiveCopyWorker
    @SourceDB     sysname = N'ProductionDB',
    @SourceTable  nvarchar(300) = N'dbo.RequestLogs',
    @DeleteSource bit = 0,
    @MaxDOP       int = 4
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @claimed TABLE (MonthStart date);
    DECLARE @ms date;

    ;WITH nextup AS
    (
        SELECT TOP (1) MonthStart
        FROM dbo.ArchiveCopyQueue WITH (UPDLOCK, READPAST, ROWLOCK)
        WHERE Status IN ('QUEUED', 'FAILED') AND Attempts < 3
        ORDER BY MonthStart
    )
    UPDATE nextup
    SET Status = 'RUNNING', Attempts = Attempts + 1, ClaimedAt = SYSUTCDATETIME()
    OUTPUT inserted.MonthStart INTO @claimed;

    SELECT @ms = MonthStart FROM @claimed;
    IF @ms IS NULL RETURN;          -- nothing to do

    BEGIN TRY
        EXEC dbo.usp_ArchiveRequestLogs_Monthly
             @MonthStart = @ms, @SourceDB = @SourceDB, @SourceTable = @SourceTable,
             @DeleteSource = @DeleteSource, @MaxDOP = @MaxDOP;

        UPDATE dbo.ArchiveCopyQueue SET Status = 'DONE', DoneAt = SYSUTCDATETIME()
        WHERE MonthStart = @ms;
    END CATCH
    BEGIN
        UPDATE dbo.ArchiveCopyQueue SET Status = 'FAILED'
        WHERE MonthStart = @ms;
        THROW;
    END CATCH
END
GO

/* ---- 4c) Dispatcher: queue a month range, start N parallel workers ------ */
CREATE OR ALTER PROCEDURE dbo.usp_ArchiveRequestLogs_Dispatch
    @FromMonth   date,
    @ToMonth     date,
    @MaxParallel int = 4,
    @JobName     sysname = N'Archive RequestLogs Worker'
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @d date = DATEFROMPARTS(YEAR(@FromMonth), MONTH(@FromMonth), 1);
    SET @ToMonth = DATEFROMPARTS(YEAR(@ToMonth), MONTH(@ToMonth), 1);

    WHILE @d <= @ToMonth
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM dbo.ArchiveCopyQueue WHERE MonthStart = @d)
            INSERT dbo.ArchiveCopyQueue (MonthStart) VALUES (@d);
        SET @d = DATEADD(month, 1, @d);
    END

    -- Start up to @MaxParallel workers; ignore "job already running" errors.
    DECLARE @i int = 1;
    WHILE @i <= @MaxParallel
    BEGIN
        BEGIN TRY
            EXEC msdb.dbo.sp_start_job @job_name = @JobName;
        END TRY
        BEGIN CATCH /* job already running -> fine */ END CATCH
        SET @i += 1;
    END
END
GO

/* ============================================================================
   SECTION 5 - SQL Agent worker job (run connected to msdb, once)
   ============================================================================ */
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'Archive RequestLogs Worker')
    EXEC msdb.dbo.sp_delete_job @job_name = N'Archive RequestLogs Worker';
GO
EXEC msdb.dbo.sp_add_job @job_name = N'Archive RequestLogs Worker', @enabled = 1;
EXEC msdb.dbo.sp_add_jobstep
     @job_name = N'Archive RequestLogs Worker',
     @step_name = N'Claim and archive one month',
     @subsystem = N'TSQL',
     @database_name = N'ArchiveDB',
     @command = N'EXEC dbo.usp_ArchiveCopyWorker @SourceDB = N''ProductionDB'', @DeleteSource = 0, @MaxDOP = 4;',
     @on_success_action = 1, @on_fail_action = 2, @retry_attempts = 0;
EXEC msdb.dbo.sp_add_jobserver @job_name = N'Archive RequestLogs Worker';
GO

/* ============================================================================
   SECTION 6 - Usage
   ============================================================================
-- Put the ARCHIVE database into BULK_LOGGED for the load window
-- (revert to FULL/SIMPLE afterwards). TABLOCK + BULK_LOGGED/SIMPLE is what
-- makes the INSERT minimally logged.
--   ALTER DATABASE [ArchiveDB] SET RECOVERY BULK_LOGGED;

-- Copy one month manually (dry run - nothing deleted from production):
EXEC ArchiveDB.dbo.usp_ArchiveRequestLogs_Monthly @MonthStart = '2026-08-01', @DeleteSource = 0;

-- Queue a range and run 4 workers in parallel (each claims a different month):
EXEC ArchiveDB.dbo.usp_ArchiveRequestLogs_Dispatch @FromMonth = '2026-01-01', @ToMonth = '2026-08-01', @MaxParallel = 4;

-- Watch progress:
SELECT MonthStart, Status, Attempts, ClaimedAt, DoneAt FROM ArchiveDB.dbo.ArchiveCopyQueue ORDER BY MonthStart;
SELECT RunId, MonthStart, RowsSource, RowsCopied, RowsDeleted, Status, DurationSec, ErrorMessage
FROM ArchiveDB.dbo.ArchiveCopyLog ORDER BY LogId DESC;

-- Verify partition row counts:
SELECT $PARTITION.pf_RequestLogs_Monthly([Timestamp]) AS PartitionNo,
       MIN([Timestamp]) AS MinTs, MAX([Timestamp]) AS MaxTs, COUNT_BIG(*) AS Rows
FROM ArchiveDB.dbo.RequestLogs
GROUP BY $PARTITION.pf_RequestLogs_Monthly([Timestamp])
ORDER BY PartitionNo;
============================================================================ */
