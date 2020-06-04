/****** Object:  Database [eventlog]    Script Date: 6/4/2020 10:36:02 ******/
CREATE DATABASE [eventlog]  (EDITION = 'Standard', SERVICE_OBJECTIVE = 'S2', MAXSIZE = 250 GB);
GO

ALTER DATABASE [eventlog] SET ANSI_NULL_DEFAULT OFF 
GO

ALTER DATABASE [eventlog] SET ANSI_NULLS OFF 
GO

ALTER DATABASE [eventlog] SET ANSI_PADDING OFF 
GO

ALTER DATABASE [eventlog] SET ANSI_WARNINGS OFF 
GO

ALTER DATABASE [eventlog] SET ARITHABORT OFF 
GO

ALTER DATABASE [eventlog] SET AUTO_SHRINK OFF 
GO

ALTER DATABASE [eventlog] SET AUTO_UPDATE_STATISTICS ON 
GO

ALTER DATABASE [eventlog] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO

ALTER DATABASE [eventlog] SET CONCAT_NULL_YIELDS_NULL OFF 
GO

ALTER DATABASE [eventlog] SET NUMERIC_ROUNDABORT OFF 
GO

ALTER DATABASE [eventlog] SET QUOTED_IDENTIFIER OFF 
GO

ALTER DATABASE [eventlog] SET RECURSIVE_TRIGGERS OFF 
GO

ALTER DATABASE [eventlog] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO

ALTER DATABASE [eventlog] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO

ALTER DATABASE [eventlog] SET ALLOW_SNAPSHOT_ISOLATION ON 
GO

ALTER DATABASE [eventlog] SET PARAMETERIZATION SIMPLE 
GO

ALTER DATABASE [eventlog] SET READ_COMMITTED_SNAPSHOT ON 
GO

ALTER DATABASE [eventlog] SET  MULTI_USER 
GO

ALTER DATABASE [eventlog] SET ENCRYPTION ON
GO

ALTER DATABASE [eventlog] SET QUERY_STORE = ON
GO

ALTER DATABASE [eventlog] SET QUERY_STORE (OPERATION_MODE = READ_WRITE, CLEANUP_POLICY = (STALE_QUERY_THRESHOLD_DAYS = 30), DATA_FLUSH_INTERVAL_SECONDS = 900, INTERVAL_LENGTH_MINUTES = 60, MAX_STORAGE_SIZE_MB = 100, QUERY_CAPTURE_MODE = AUTO, SIZE_BASED_CLEANUP_MODE = AUTO)
GO

ALTER DATABASE [eventlog] SET  READ_WRITE 
GO

/****** Object:  Table [dbo].[file_history]    Script Date: 6/4/2020 10:36:27 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[file_history](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[timestamp] [datetime2](7) NULL,
	[sid] [varchar](256) NULL,
	[username] [varchar](256) NULL,
	[object_type] [varchar](256) NULL,
	[object_name] [varchar](512) NULL,
	[process_id] [int] NULL,
	[process_name] [varchar](128) NULL,
	[access_string] [text] NULL,
	[perm_read_list] [bit] NULL,
	[perm_write_create] [bit] NULL,
	[perm_append_create_pipe] [bit] NULL,
	[perm_read_ea] [bit] NULL,
	[perm_write_ea] [bit] NULL,
	[perm_execute_traverse] [bit] NULL,
	[perm_delete_dir] [bit] NULL,
	[perm_read_attrib] [bit] NULL,
	[perm_write_attrib] [bit] NULL,
	[perm_delete] [bit] NULL,
	[perm_read_acl] [bit] NULL,
	[perm_write_dacl] [bit] NULL,
	[perm_write_owner] [bit] NULL,
	[perm_synchronize] [bit] NULL,
	[perm_access_sacl] [bit] NULL,
	[computername] [varchar](256) NULL,
 CONSTRAINT [PK_file_history] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Object:  Table [dbo].[group_history]    Script Date: 6/4/2020 10:36:40 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[group_history](
	[timestamp] [datetime2](7) NULL,
	[reporting_machine] [varchar](128) NULL,
	[action] [int] NULL,
	[member_sid] [varchar](128) NULL,
	[member_name] [varchar](128) NULL,
	[group_sid] [varchar](128) NULL,
	[group_name] [varchar](128) NULL,
	[actor_sid] [varchar](128) NULL,
	[actor_name] [varchar](128) NULL,
	[actor_logon_id] [int] NULL,
	[actor_domainname] [varchar](128) NULL,
	[group_domainname] [varchar](128) NULL,
	[action_string] [varchar](128) NULL,
	[id] [int] IDENTITY(1,1) NOT NULL,
 CONSTRAINT [PK_group_history] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO


/****** Object:  Table [dbo].[logon_history]    Script Date: 6/4/2020 10:36:48 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[logon_history](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[timestamp] [datetime2](7) NULL,
	[subject_username] [varchar](128) NULL,
	[subject_domain] [varchar](128) NULL,
	[target_username] [varchar](128) NULL,
	[target_domain] [varchar](128) NULL,
	[logon_id] [int] NULL,
	[logon_type] [int] NULL,
	[logon_type_string] [varchar](64) NULL,
	[workstation] [varchar](128) NULL,
	[source_ip] [varchar](128) NULL,
	[source_port] [int] NULL,
	[direction] [bit] NULL,
	[direction_string] [varchar](32) NULL,
 CONSTRAINT [PK_logon_history] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Object:  Table [dbo].[raw_events]    Script Date: 6/4/2020 10:37:07 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[raw_events](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[level] [int] NULL,
	[level_string] [varchar](64) NULL,
	[time_logged] [datetime2](7) NULL,
	[time_captured] [datetime2](7) NULL,
	[machine_name] [varchar](128) NULL,
	[source] [varchar](64) NULL,
	[event_id] [int] NULL,
	[event_string] [text] NULL,
	[event_xml] [text] NULL,
 CONSTRAINT [PK_asdfasdf] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO


/****** Object:  Table [dbo].[user_management_history]    Script Date: 6/4/2020 10:37:18 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[user_management_history](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[timestamp] [datetime2](7) NULL,
	[action] [varchar](128) NULL,
	[reporting_machine] [varchar](256) NULL,
	[subject_username] [varchar](256) NULL,
	[subject_domainname] [varchar](256) NULL,
	[subject_sid] [varchar](256) NULL,
	[subject_logon_id] [int] NULL,
	[target_username] [varchar](256) NULL,
	[target_domainname] [varchar](256) NULL,
	[target_sid] [varchar](256) NULL,
	[target_displayname] [varchar](256) NULL,
	[target_upn] [varchar](256) NULL,
 CONSTRAINT [PK_user_management_history] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO







