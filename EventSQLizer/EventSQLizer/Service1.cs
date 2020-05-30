using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Xml;
using Microsoft.Win32;
using Newtonsoft.Json;

namespace EventSQLizer
{
    // object for serialization and sending to Nagios
    class NagiosAlert
    {
        public enum severity_level
        {
            OK,
            WARN,
            CRIT,
            UNKNOWN
        }

        public String host_name;
        public string service_name;
        public Int32 service_status;
        public string service_status_description;

        public NagiosAlert(int severity, string description)
        {
            string computername = System.Net.Dns.GetHostName().ToLower();

            host_name = String.Format("rctc.passive.{0}", computername);
            service_name = "wec_alerts";
            service_status = severity;
            service_status_description = description;
        }
    }

    // great missed opportunity for making a factory
    class Alert
    {
        public int severity;
        public string text;
    }
    
    // basic class for graphite host connection info
    class RemoteHost
        {
        public string hostname;
        public int port;
        
        public RemoteHost(string hostname, int port)
            {
            this.hostname = hostname;
            this.port = port;
            }
        }

    // simple logging class
    class Logger
    {
        private StreamWriter logh;
        public Logger(StreamWriter loghandle)
        {
            logh = loghandle;
        }

        // simple logging function, includes the time.
        public void log(string line)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            logh.Write(String.Format("[{0}]: {1}\n", timestamp, line));
            logh.Flush();
        }
    }

    class EventClassifier
    {
        // create a list of interesting events, for fast filtering.
        private Dictionary<int, Action<EventRecord>> handlers = new Dictionary<int, Action<EventRecord>>();
        private readonly List<int> interesting_events = new List<int>();

        // and a list of sql queries to run, based on what we extract from this event.
        public List<string> sql_queries = new List<string>();

        // and a list of alerts to be queued
        public List<Alert> alerts = new List<Alert>();

        // and a list of blacklisted event IDs
        private List<int> eventid_blacklist = new List<int>();
        public bool event_blocked = false;// true if this instance blocked an event.

        // dict of human-readable logon types
        public Dictionary<int, string> logon_types = new Dictionary<int, string>();

        // dict of human-readable audit policy subcategories
        public Dictionary<string, string> audit_policy_subcats = new Dictionary<string, string>();

        // local logger reference
        private Logger logger;

        // constructor
        public EventClassifier(Logger passed_logger, EventRecord e)
        {
            // set up local copy of logger
            logger = passed_logger;

            // register blackisted ids
            eventid_blacklist.Add(5152);// Windows Firewall noise
            eventid_blacklist.Add(5156);// Windows Firewall noise
            eventid_blacklist.Add(5157);// Windows Firewall noise

            // register logon types
            logon_types.Add(0, @"Unknown");
            logon_types.Add(2, @"Interactive");
            logon_types.Add(3, @"Network");
            logon_types.Add(4, @"Batch");
            logon_types.Add(5, @"Service");
            logon_types.Add(7, @"Unlock");
            logon_types.Add(8, @"NetworkCleartext");
            logon_types.Add(9, @"NewCredentials");
            logon_types.Add(10, @"RemoteInteractive");
            logon_types.Add(11, @"CachedInteractive");
            // custom below here
            logon_types.Add(1000, @"UserInitatedLogoff");
            logon_types.Add(1001, @"Lock");
            logon_types.Add(1002, @"Unlock");
            logon_types.Add(1010, @"SessionReconnect");
            logon_types.Add(1011, @"SessionDisconnect");

            // register policy change subcategories
            audit_policy_subcats.Add("{0CCE9210-69AE-11D9-BED3-505054503030}", "Security State Change");
            audit_policy_subcats.Add("{0CCE9211-69AE-11D9-BED3-505054503030}", "Security System Extension");
            audit_policy_subcats.Add("{0CCE9212-69AE-11D9-BED3-505054503030}", "System Integrity");
            audit_policy_subcats.Add("{0CCE9213-69AE-11D9-BED3-505054503030}", "IPsec Driver");
            audit_policy_subcats.Add("{0CCE9214-69AE-11D9-BED3-505054503030}", "Other System Events");
            audit_policy_subcats.Add("{0CCE9215-69AE-11D9-BED3-505054503030}", "Logon");
            audit_policy_subcats.Add("{0CCE9216-69AE-11D9-BED3-505054503030}", "Logoff");
            audit_policy_subcats.Add("{0CCE9217-69AE-11D9-BED3-505054503030}", "Account Lockout");
            audit_policy_subcats.Add("{0CCE9218-69AE-11D9-BED3-505054503030}", "IPsec Main Mode");
            audit_policy_subcats.Add("{0CCE9219-69AE-11D9-BED3-505054503030}", "IPsec Quick Mode");
            audit_policy_subcats.Add("{0CCE921A-69AE-11D9-BED3-505054503030}", "IPsec Extended Mode");
            audit_policy_subcats.Add("{0CCE921B-69AE-11D9-BED3-505054503030}", "Special Logon");
            audit_policy_subcats.Add("{0CCE921C-69AE-11D9-BED3-505054503030}", "Other Logon/Logoff Events");
            audit_policy_subcats.Add("{0CCE9243-69AE-11D9-BED3-505054503030}", "Network Policy Server");
            audit_policy_subcats.Add("{0CCE9247-69AE-11D9-BED3-505054503030}", "User / Device Claims");
            audit_policy_subcats.Add("{0CCE9249-69AE-11D9-BED3-505054503030}", "Group Membership");
            audit_policy_subcats.Add("{0CCE921D-69AE-11D9-BED3-505054503030}", "File System");
            audit_policy_subcats.Add("{0CCE921E-69AE-11D9-BED3-505054503030}", "Registry");
            audit_policy_subcats.Add("{0CCE921F-69AE-11D9-BED3-505054503030}", "Kernel Object");
            audit_policy_subcats.Add("{0CCE9220-69AE-11D9-BED3-505054503030}", "SAM");
            audit_policy_subcats.Add("{0CCE9221-69AE-11D9-BED3-505054503030}", "Certification Services");
            audit_policy_subcats.Add("{0CCE9222-69AE-11D9-BED3-505054503030}", "Application Generated");
            audit_policy_subcats.Add("{0CCE9223-69AE-11D9-BED3-505054503030}", "Handle Manipulation");
            audit_policy_subcats.Add("{0CCE9224-69AE-11D9-BED3-505054503030}", "File Share");
            audit_policy_subcats.Add("{0CCE9225-69AE-11D9-BED3-505054503030}", "Filtering Platform Packet Drop");
            audit_policy_subcats.Add("{0CCE9226-69AE-11D9-BED3-505054503030}", "Filtering Platform Connection");
            audit_policy_subcats.Add("{0CCE9227-69AE-11D9-BED3-505054503030}", "Other Object Access Events");
            audit_policy_subcats.Add("{0CCE9244-69AE-11D9-BED3-505054503030}", "Detailed File Share");
            audit_policy_subcats.Add("{0CCE9245-69AE-11D9-BED3-505054503030}", "Removable Storage");
            audit_policy_subcats.Add("{0CCE9246-69AE-11D9-BED3-505054503030}", "Central Policy Staging");
            audit_policy_subcats.Add("{0CCE9228-69AE-11D9-BED3-505054503030}", "Sensitive Privilege Use");
            audit_policy_subcats.Add("{0CCE9229-69AE-11D9-BED3-505054503030}", "Non Sensitive Privilege Use");
            audit_policy_subcats.Add("{0CCE922A-69AE-11D9-BED3-505054503030}", "Other Privilege Use Events");
            audit_policy_subcats.Add("{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation");
            audit_policy_subcats.Add("{0CCE922C-69AE-11D9-BED3-505054503030}", "Process Termination");
            audit_policy_subcats.Add("{0CCE922D-69AE-11D9-BED3-505054503030}", "DPAPI Activity");
            audit_policy_subcats.Add("{0CCE922E-69AE-11D9-BED3-505054503030}", "RPC Events");
            audit_policy_subcats.Add("{0CCE9248-69AE-11D9-BED3-505054503030}", "Plug and Play Events");
            audit_policy_subcats.Add("{0CCE924A-69AE-11D9-BED3-505054503030}", "Token Right Adjusted Events");
            audit_policy_subcats.Add("{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Policy Change");
            audit_policy_subcats.Add("{0CCE9230-69AE-11D9-BED3-505054503030}", "Authentication Policy Change");
            audit_policy_subcats.Add("{0CCE9231-69AE-11D9-BED3-505054503030}", "Authorization Policy Change");
            audit_policy_subcats.Add("{0CCE9232-69AE-11D9-BED3-505054503030}", "MPSSVC Rule-Level Policy Change");
            audit_policy_subcats.Add("{0CCE9233-69AE-11D9-BED3-505054503030}", "Filtering Platform Policy Change");
            audit_policy_subcats.Add("{0CCE9234-69AE-11D9-BED3-505054503030}", "Other Policy Change Events");
            audit_policy_subcats.Add("{0CCE9235-69AE-11D9-BED3-505054503030}", "User Account Management");
            audit_policy_subcats.Add("{0CCE9236-69AE-11D9-BED3-505054503030}", "Computer Account Management");
            audit_policy_subcats.Add("{0CCE9237-69AE-11D9-BED3-505054503030}", "Security Group Management");
            audit_policy_subcats.Add("{0CCE9238-69AE-11D9-BED3-505054503030}", "Distribution Group Management");
            audit_policy_subcats.Add("{0CCE9239-69AE-11D9-BED3-505054503030}", "Application Group Management");
            audit_policy_subcats.Add("{0CCE923A-69AE-11D9-BED3-505054503030}", "Other Account Management Events");
            audit_policy_subcats.Add("{0CCE923B-69AE-11D9-BED3-505054503030}", "Directory Service Access");
            audit_policy_subcats.Add("{0CCE923C-69AE-11D9-BED3-505054503030}", "Directory Service Changes");
            audit_policy_subcats.Add("{0CCE923D-69AE-11D9-BED3-505054503030}", "Directory Service Replication");
            audit_policy_subcats.Add("{0CCE923E-69AE-11D9-BED3-505054503030}", "Detailed Directory Service Replication");
            audit_policy_subcats.Add("{0CCE923F-69AE-11D9-BED3-505054503030}", "Credential Validation");
            audit_policy_subcats.Add("{0CCE9240-69AE-11D9-BED3-505054503030}", "Kerberos Service Ticket Operations");
            audit_policy_subcats.Add("{0CCE9241-69AE-11D9-BED3-505054503030}", "Other Account Logon Events");
            audit_policy_subcats.Add("{0CCE9242-69AE-11D9-BED3-505054503030}", "Kerberos Authentication Service");

            // register handlers    
            handlers[4663] = event4663;//   file access
            handlers[4624] = event4624;//   logons
            //handlers[4625] = event4625;// failed logons
            handlers[4634] = event4634;//   logoffs
            handlers[4647] = event4647;//   logoffs
            handlers[4800] = event4800;//   locks
            handlers[4801] = event4801;//   unlocks
            handlers[4778] = event4778;//   session reconnects
            handlers[4779] = event4779;//   session disconnects
            handlers[4732] = event4732;//   security group member added
            handlers[4733] = event4733;//   security group member removed
            handlers[4728] = event4732;//   security group member added - domain
            handlers[4729] = event4733;//   security group member removed - domain
            handlers[5038] = event5038;//   a system file failed hash check
            handlers[5035] = event5035;//   the Windows firewall kernel
            handlers[4720] = event4720;//   A user account was created
            handlers[4726] = event4726;//   A user account was deleted
            handlers[4722] = event4722;//   A user account was enabled
            handlers[4725] = event4725;//   A user account was disabled
            handlers[4740] = event4740;//   A user account was locked out
            handlers[4767] = event4767;//   A user account was unlocked

            // create list of handlers
            interesting_events = handlers.Keys.ToList();

            // fire off the appropriate handler based on the event ID
            if (interesting_events.Contains(e.Id))
            {
                //Console.WriteLine("Fired hook event{0}", e.Id);
                Action<EventRecord> lambda;
                lambda = handlers[e.Id];
                try { lambda(e); }
                catch(Exception ex)
                {
                    logger.log(String.Format("Error running handler event{0}: {1}", e.Id, ex.ToString()));
                }

            }

            // check if event id is blacklisted
            if (eventid_blacklist.Contains(e.Id))
            {
                event_blocked = true;
                return;
            }

            // unless blacklisted, generate a raw log entry.
            try { eventRaw(e); }
            catch (Exception ex)
            {
                logger.log(String.Format("Error running handler eventRaw: {0}", ex.ToString()));
            }
        }

        // handlers
        // Local file access audit record.  4663 means that this right was *exercised*, IOW it was used, not just checked against. - LOGS
        private void event4663(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4663";

            // access mask dict
            Dictionary<int, string> access_bits = new Dictionary<int, string>
                {
                    { 0x1, @"Read File/List Dir" },
                    { 0x2, @"Write/Create File" },
                    { 0x4, @"Append File/Create Dir/Create Pipe" },
                    { 0x8, @"Read Extended Attributes" },
                    { 0x10, @"Write Extended Attributes" },
                    { 0x20, @"Execute File/Traverse Dir" },
                    { 0x40, @"Delete Dir" },
                    { 0x80, @"Read Attributes" },
                    { 0x100, @"Write Attributes" },
                    { 0x10000, @"Delete Object" },
                    { 0x20000, @"Read ACL" },
                    { 0x40000, @"Write DACL" },
                    { 0x80000, @"Change Owner" },
                    { 0x100000, @"Synchronize" },
                    { 0x1000000, @"Access SACL" }
                };

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the data values we care about
            List<int> permbits = new List<int>();
            string sid = "";
            string username = "";
            string object_type = "";
            string object_name = "";
            string process_name = "";
            string computer_name;
            try { computer_name = e.MachineName; } catch { computer_name = "Unset!!"; }
            string access_string = "";
            int access_mask = 0;
            string process_id = "";

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                try
                {
                    string key = datum.Attributes["Name"].Value;
                    string value = datum.InnerText;
                    switch (key)
                    {
                        case @"SubjectUserSid":
                            sid = value;
                            break;
                        case @"SubjectUserName":
                            username = value;
                            break;
                        case @"ObjectType":
                            object_type = value;
                            break;
                        case @"ObjectName":
                            object_name = value.Replace(@"'", @"''");
                            break;
                        case @"AccessMask":
                            access_mask = Convert.ToInt32(value, 16);
                            break;
                        case @"process_id":
                            process_id = value;
                            break;
                        case @"process_name":
                            process_name = value;
                            break;
                    }
                }
                catch
                {
                    logger.log(String.Format("{0} - Trouble parsing event XML", thisMethod));
                    continue;
                }
            }

            // create the human-readable access_string
            foreach (int mask in access_bits.Keys.ToList())
            {
                if ((mask & access_mask) > 0)
                {
                    access_string = String.Format("{0}, ", access_bits[mask]);
                    permbits.Add(1);
                }
                else
                    permbits.Add(0);
            }

            // Generate the SQL query and append it.
            string sql;
            sql = "INSERT INTO file_history ( timestamp, sid, username, computername, object_type, object_name, process_id, process_name, access_string";
            sql += ", perm_read_list, perm_write_create, perm_append_create_pipe, perm_read_ea, perm_write_ea, perm_execute_traverse";
            sql += ", perm_delete_dir, perm_read_attrib, perm_write_attrib, perm_delete, perm_read_acl, perm_write_dacl, perm_write_owner";
            sql += ", perm_synchronize, perm_access_sacl )";
            sql += " VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}'";
            sql = String.Format(sql, e.TimeCreated, sid, username, computer_name, object_type, object_name, process_id, process_name, access_string);
            foreach (int bit in permbits)
                sql += String.Format(", '{0}'", bit);
            sql += " );";

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            return;
        }

        // User logon. - LOGS
        private void event4624(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4624";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string subject_username = "";
            string subject_domain = "";
            string target_username = "";
            string target_domain = "";
            int logon_id = 0;
            int logon_type = 0;
            string logon_type_string = "";
            string workstation = "";
            string source_ip = "";
            int source_port = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"SubjectUserName":
                        try { subject_username = value; } catch { subject_username = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { subject_domain = value; } catch { subject_domain = @""; }
                        break;
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domain = value; } catch { target_domain = @""; }
                        break;
                    case @"TargetLogonId":
                        try { logon_id = Convert.ToInt32(value, 16); } catch { logon_id = 0; }
                        break;
                    case @"LogonType":
                        try { logon_type = Convert.ToInt32(value); } catch { logon_type = 0; }
                        logon_type_string = logon_types[logon_type];
                        break;
                    case @"WorkstationName":
                        try { workstation = value; } catch { workstation = @""; }
                        break;
                    case @"IpAddress":
                        try { source_ip = value; } catch { source_ip = @""; }
                        break;
                    case @"IpPort":
                        try { source_port = Convert.ToInt32(value); } catch { source_port = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO logon_history ( timestamp, direction, direction_string, subject_username, subject_domain, target_username, target_domain, logon_id, logon_type, logon_type_string, workstation, source_ip, source_port )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}' );", timestamp, 0, @"Logon", subject_username, subject_domain, target_username, target_domain, logon_id, logon_type, logon_type_string, workstation, source_ip, source_port);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            /*
            // GENERATES LOTS OF NOISE FOR DEBUGGING!!!!!!!!!   Generate the alert and append it
            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.WARN,
                text = String.Format("{0}: User {1} logged onto machine {2}!", timestamp, target_username, workstation)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert!", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }
            */
            return;
        }

        // User logoff - LOGS
        private void event4634(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4634";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string target_username = "";
            string target_domain = "";
            int logon_id = 0;
            int logon_type = 0;
            string logon_type_string = "";

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domain = value; } catch { target_domain = @""; }
                        break;
                    case @"TargetLogonId":
                        try { logon_id = Convert.ToInt32(value, 16); } catch { logon_id = 0; }
                        break;
                    case @"LogonType":
                        try { logon_type = Convert.ToInt32(value); } catch { logon_type = 0; }
                        logon_type_string = logon_types[logon_type];
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO logon_history ( timestamp, direction, direction_string, target_username, target_domain, logon_id, logon_type, logon_type_string )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}' );", timestamp, 1, @"Logoff", target_username, target_domain, logon_id, logon_type, logon_type_string);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }
            return;
        }

        // User initiated logoff - LOGS
        private void event4647(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4647";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string target_username = "";
            string target_domain = "";
            int logon_id = 0;
            int logon_type = 1000;
            string workstation = e.MachineName;
            string logon_type_string = logon_types[logon_type];

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domain = value; } catch { target_domain = @""; }
                        break;
                    case @"TargetLogonId":
                        try { logon_id = Convert.ToInt32(value, 16); } catch { logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO logon_history ( timestamp, direction, direction_string, target_username, target_domain, logon_id, logon_type, logon_type_string, workstation )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}' );", timestamp, 1, @"Logoff", target_username, target_domain, logon_id, logon_type, logon_type_string, workstation);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }
            return;
        }

        // Workstation was locked - LOGS
        private void event4800(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4800";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string target_username = "";
            string target_domain = "";
            string workstation = e.MachineName;
            int logon_id = 0;
            int logon_type = 1001;
            string logon_type_string = logon_types[logon_type];

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domain = value; } catch { target_domain = @""; }
                        break;
                    case @"TargetLogonId":
                        try { logon_id = Convert.ToInt32(value, 16); } catch { logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO logon_history ( timestamp, direction, direction_string, target_username, target_domain, logon_id, logon_type, logon_type_string, workstation )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}' );", timestamp, 1, @"Logoff", target_username, target_domain, logon_id, logon_type, logon_type_string, workstation);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }
            return;
        }

        // Workstation was unlocked - LOGS
        private void event4801(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4801";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string target_username = "";
            string target_domain = "";
            string workstation = e.MachineName;
            int logon_id = 0;
            int logon_type = 1002;
            string logon_type_string = logon_types[logon_type];

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domain = value; } catch { target_domain = @""; }
                        break;
                    case @"TargetLogonId":
                        try { logon_id = Convert.ToInt32(value, 16); } catch { logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO logon_history ( timestamp, direction, direction_string, target_username, target_domain, logon_id, logon_type, logon_type_string, workstation )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}' );", timestamp, 0, @"Logon", target_username, target_domain, logon_id, logon_type, logon_type_string, workstation);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }
            return;
        }

        // User reconnected to a running session - LOGS
        private void event4778(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4778";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string target_username = "";
            string target_domain = "";
            string workstation = e.MachineName;
            int logon_id = 0;
            int logon_type = 1010;
            string logon_type_string = logon_types[logon_type];

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }


            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"AccountName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"AccountDomain":
                        try { target_domain = value; } catch { target_domain = @""; }
                        break;
                    case @"LogonID":
                        try { logon_id = Convert.ToInt32(value, 16); } catch { logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO logon_history ( timestamp, direction, direction_string, target_username, target_domain, logon_id, logon_type, logon_type_string, workstation )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}' );", timestamp, 0, @"Logon", target_username, target_domain, logon_id, logon_type, logon_type_string, workstation);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }
            return;
        }

        // User disconnected from session - LOGS
        private void event4779(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4779";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string target_username = "";
            string target_domain = "";
            string workstation = e.MachineName;
            int logon_id = 0;
            int logon_type = 1011;
            string logon_type_string = logon_types[logon_type];

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }


            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"AccountName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"AccountDomain":
                        try { target_domain = value; } catch { target_domain = @""; }
                        break;
                    case @"LogonID":
                        try { logon_id = Convert.ToInt32(value, 16); } catch { logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO logon_history ( timestamp, direction, direction_string, target_username, target_domain, logon_id, logon_type, logon_type_string, workstation )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}' );", timestamp, 1, @"Logoff", target_username, target_domain, logon_id, logon_type, logon_type_string, workstation);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }
            return;
        }

        // User was added to a group - ALERTS
        private void event4732(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4732";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine = e.MachineName;
            string member_name = "";
            string member_sid = "";
            string group_sid = "";
            string group_name = "";
            string group_domainname = "";
            string actor_sid = "";
            string actor_name = "";
            string actor_domainname = "";
            int actor_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"MemberName":
                        try { member_name = value; } catch { member_name = @""; }
                        break;
                    case @"MemberSid":
                        try { member_sid = value; } catch { member_sid = @""; }
                        break;
                    case @"TargetUserName":
                        try { group_name = value; } catch { group_name = @""; }
                        break;
                    case @"TargetDomainName":
                        try { group_domainname = value; } catch { group_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { group_sid = value; } catch { group_sid = @""; }
                        break;
                    case @"SubjectUserSid":
                        try { actor_sid = value; } catch { actor_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { actor_name = value; } catch { actor_name = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { actor_domainname = value; } catch { actor_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { actor_logon_id = Convert.ToInt32(value, 16); } catch { actor_logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO group_history ( timestamp, reporting_machine, action, action_string, member_sid, member_name, group_sid, group_name, group_domainname, actor_sid, actor_name, actor_domainname, actor_logon_id )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}' );", timestamp, reporting_machine, 0, @"Add", member_sid, member_name, group_sid, group_name, group_domainname, actor_sid, actor_name, actor_domainname, actor_logon_id);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            // Generate the alert and append it
            string friendly_member;// if possible, convert the member name into a more human-readable format for alerting
            try { friendly_member = member_name.Split(',')[0].Split('=')[1]; } catch { friendly_member = member_name; }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: \"{1}\" added member '{2}' to group '{3}' on '{4}'", timestamp, actor_name, friendly_member, group_name, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }
            
            // exit
            return;
        }

        // User was created - LOGS, ALERTS
        private void event4720(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4720";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine = e.MachineName;
            string target_username = "";
            string target_sid = "";
            string target_domainname = "";
            string target_upn = "";
            string target_displayname = "";
            string subject_username = "";
            string subject_domainname = "";
            string subject_sid = "";
            int subject_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domainname = value; } catch { target_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { target_sid = value; } catch { target_sid = @""; }
                        break;
                    case @"SubjectUserSid":
                        try { subject_sid = value; } catch { subject_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { subject_username = value; } catch { subject_username = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { subject_domainname = value; } catch { subject_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { subject_logon_id = Convert.ToInt32(value, 16); } catch { subject_logon_id = 0; }
                        break;
                    case @"DisplayName":
                        try { target_displayname = value; } catch { target_displayname = @""; }
                        break;
                    case @"UserPrincipalName":
                        try { target_upn = value; } catch { target_upn = @""; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO user_management_history ( timestamp, action, reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, target_displayname, target_upn )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}' );", timestamp, @"Create", reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, target_displayname, target_upn);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: {1} created user {2} for {3} via {4}", timestamp, subject_username, target_upn, target_displayname, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // User was deleted - LOGS, ALERTS
        private void event4726(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4726";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine = e.MachineName;
            string target_username = "";
            string target_sid = "";
            string target_domainname = "";
            string subject_username = "";
            string subject_domainname = "";
            string subject_sid = "";
            int subject_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domainname = value; } catch { target_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { target_sid = value; } catch { target_sid = @""; }
                        break;
                    case @"SubjectUserSid":
                        try { subject_sid = value; } catch { subject_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { subject_username = value; } catch { subject_username = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { subject_domainname = value; } catch { subject_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { subject_logon_id = Convert.ToInt32(value, 16); } catch { subject_logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO user_management_history ( timestamp, action, reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, target_displayname, target_upn )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}' );", timestamp, @"Delete", reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, @"-", @"-");

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: {1} deleted user {2} via {3}", timestamp, subject_username, target_username, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // User was enabled - LOGS, ALERTS
        private void event4722(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4722";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine = e.MachineName;
            string target_username = "";
            string target_sid = "";
            string target_domainname = "";
            string subject_username = "";
            string subject_domainname = "";
            int subject_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domainname = value; } catch { target_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { target_sid = value; } catch { target_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { subject_username = value; } catch { subject_username = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { subject_domainname = value; } catch { subject_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { subject_logon_id = Convert.ToInt32(value, 16); } catch { subject_logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO user_management_history ( timestamp, action, reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, target_displayname, target_upn )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}' );", timestamp, @"Enable", reporting_machine, subject_username, subject_domainname, @"-", subject_logon_id, target_username, target_domainname, target_sid, @"-", @"-");

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: {1} enabled user {2} via {3}", timestamp, subject_username, target_username, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // User was disabled - LOGS, ALERTS
        private void event4725(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4725";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine = e.MachineName;
            string target_username = "";
            string target_sid = "";
            string target_domainname = "";
            string subject_username = "";
            string subject_domainname = "";
            int subject_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domainname = value; } catch { target_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { target_sid = value; } catch { target_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { subject_username = value; } catch { subject_username = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { subject_domainname = value; } catch { subject_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { subject_logon_id = Convert.ToInt32(value, 16); } catch { subject_logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO user_management_history ( timestamp, action, reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, target_displayname, target_upn )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}' );", timestamp, @"Disable", reporting_machine, subject_username, subject_domainname, @"-", subject_logon_id, target_username, target_domainname, target_sid, @"-", @"-");

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: {1} disabled user {2} via {3}", timestamp, subject_username, target_username, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // User was locked out - LOGS, ALERTS
        private void event4740(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4740";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine = e.MachineName;
            string target_username = "";
            string target_sid = "";
            string target_domainname = "";
            string subject_sid = "";
            string subject_username = "";
            string subject_domainname = "";
            int subject_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domainname = value; } catch { target_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { target_sid = value; } catch { target_sid = @""; }
                        break;
                    case @"SubjectUserSid":
                        try { subject_sid = value; } catch { subject_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { subject_username = value; } catch { subject_username = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { subject_domainname = value; } catch { subject_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { subject_logon_id = Convert.ToInt32(value, 16); } catch { subject_logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO user_management_history ( timestamp, action, reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, target_displayname, target_upn )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}' );", timestamp, @"Locked", reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, @"-", @"-");

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: {1} locked out user account {2} on {3}", timestamp, subject_username, target_username, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // User was unlocked - LOGS, ALERTS
        private void event4767(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4767";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine = e.MachineName;
            string target_username = "";
            string target_sid = "";
            string target_domainname = "";
            string subject_username = "";
            string subject_domainname = "";
            string subject_sid = "";
            int subject_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"TargetUserName":
                        try { target_username = value; } catch { target_username = @""; }
                        break;
                    case @"TargetDomainName":
                        try { target_domainname = value; } catch { target_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { target_sid = value; } catch { target_sid = @""; }
                        break;
                    case @"SubjectUserSid":
                        try { subject_sid = value; } catch { subject_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { subject_username = value; } catch { subject_username = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { subject_domainname = value; } catch { subject_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { subject_logon_id = Convert.ToInt32(value, 16); } catch { subject_logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO user_management_history ( timestamp, action, reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, target_displayname, target_upn )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}' );", timestamp, @"Disable", reporting_machine, subject_username, subject_domainname, subject_sid, subject_logon_id, target_username, target_domainname, target_sid, @"-", @"-");

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: {1} unlocked user account {2} on {3}", timestamp, subject_username, target_username, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // User was removed from a group - ALERTS
        private void event4733(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event4733";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine;
            try { reporting_machine = e.MachineName; } catch { reporting_machine = "Unset!!!"; }
            string member_name = "";
            string member_sid = "";
            string group_sid = "";
            string group_name = "";
            string group_domainname = "";
            string actor_sid = "";
            string actor_name = "";
            string actor_domainname = "";
            int actor_logon_id = 0;

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                switch (key)
                {
                    case @"MemberName":
                        try { member_name = value; } catch { member_name = @""; }
                        break;
                    case @"MemberSid":
                        try { member_sid = value; } catch { member_sid = @""; }
                        break;
                    case @"TargetUserName":
                        try { group_name = value; } catch { group_name = @""; }
                        break;
                    case @"TargetDomainName":
                        try { group_domainname = value; } catch { group_domainname = @""; }
                        break;
                    case @"TargetSid":
                        try { group_sid = value; } catch { group_sid = @""; }
                        break;
                    case @"SubjectUserSid":
                        try { actor_sid = value; } catch { actor_sid = @""; }
                        break;
                    case @"SubjectUserName":
                        try { actor_name = value; } catch { actor_name = @""; }
                        break;
                    case @"SubjectDomainName":
                        try { actor_domainname = value; } catch { actor_domainname = @""; }
                        break;
                    case @"SubjectLogonId":
                        try { actor_logon_id = Convert.ToInt32(value, 16); } catch { actor_logon_id = 0; }
                        break;
                }
            }

            // Generate the SQL query and append it.
            string sql;

            sql = @"INSERT INTO group_history ( timestamp, reporting_machine, action, action_string, member_sid, member_name, group_sid, group_name, group_domainname, actor_sid, actor_name, actor_domainname, actor_logon_id )";
            sql += String.Format(" VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}' );", timestamp, reporting_machine, 1, @"Remove", member_sid, member_name, group_sid, group_name, group_domainname, actor_sid, actor_name, actor_domainname, actor_logon_id);

            try { sql_queries.Add(sql); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }

            // Generate the alert and append it
            string friendly_member;// if possible, convert the member name into a more human-readable format for alerting
            try { friendly_member = member_name.Split(',')[0].Split('=')[1]; } catch { friendly_member = member_name; }

            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.CRIT,
                text = String.Format("[{0}]: \"{1}\" removed member '{2}' from group '{3}' on '{4}'", timestamp, actor_name, friendly_member, group_name, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert!", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // System file failed hash check - ALERTS - Doesn't record in SQL
        private void event5038(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event5038";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine;
            try { reporting_machine = e.MachineName; } catch { reporting_machine = "Unset!!!"; }
            string filename = "";



            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            foreach (XmlElement datum in data)
            {
                string key = datum.Attributes["Name"].Value;
                string value = datum.InnerText;
                
                // are you fucking kidding me with this param name MS?
                if(key == @"param1")
                {
                    try { filename = value; } catch { filename = @""; }
                    break;
                }
            }

            // Generate the alert and append it
            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.WARN,
                text = String.Format("[{0}]: Machine {1} reports file \"{2}\" corrupted!", timestamp, reporting_machine, filename)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert!", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // Windows firewall failure - ALERTS - Doesn't record in SQL
        private void event5035(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "event5035";

            // turn the XML text into an object
            XmlDocument xml = new XmlDocument();
            try { xml.LoadXml(e.ToXml()); }
            catch
            {
                logger.log(String.Format("{0} - Couldn't convert event to XML.", thisMethod));
                return;
            }

            // prepare to extract the details
            string timestamp;
            string reporting_machine;
            string device_path;
            string nic_name;
            try { reporting_machine = e.MachineName; } catch { reporting_machine = "Unset!!!"; };

            // timestamp is non-optional
            try { timestamp = e.TimeCreated.ToString(); }
            catch (Exception)
            {
                logger.log(String.Format("{0} - Failed to extract timestamp, event skipped.", thisMethod));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // collect data attributes
            XmlNodeList data = xml.GetElementsByTagName("Data");
            try { device_path = data[0].InnerText; } catch { device_path = @"Unknown"; }
            try { nic_name = data[1].InnerText; } catch { nic_name = @"Unknown"; }

            // Generate the alert and append it
            Alert alert = new Alert
            {
                severity = (int)NagiosAlert.severity_level.WARN,
                text = String.Format("[{0}]: Firewall kernel failure, device path '{1}', NIC name '{2}' on '{3}'.", timestamp, device_path, nic_name, reporting_machine)
            };

            try { alerts.Add(alert); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue Alert!", thisMethod));
                EventSQLAgent.lost_alerts += 1;
            }

            // exit
            return;
        }

        // a raw event record, fires for all events.
        private void eventRaw(EventRecord e)
        {
            // for clearer logging
            string thisMethod = "eventRaw";

            // standard fields
            string level;
            string level_string;
            string time_logged;
            string time_captured;
            string machine_name;
            string source;
            string event_id;
            string event_string;
            string event_xml;

            // extract essential fields first
            try
            {
                level = e.Level.ToString();
                try { level_string = e.LevelDisplayName; } catch { level_string = "Undefined";  }
                time_captured = DateTime.Now.ToString("yyyy -MM-dd HH:mm:ss.fff");
                time_logged = e.TimeCreated.ToString();
                event_xml = e.ToXml().Replace(@"'", @"''");
                event_id = e.Id.ToString();
            }
            catch(Exception ex)
            {
                logger.log(String.Format("Failed to log event ID {0}!!\n'{1}'\n\n", e.Id, ex.ToString()));
                EventSQLAgent.lost_events += 1;
                return;
            }

            // then individually wrap non-essentials
            try { source = e.ProviderName; } catch { source = "Source not specified."; }
            try { event_string = e.FormatDescription().Replace(@"'", @"''"); } catch { event_string = "No description provided"; }
            try { machine_name = e.MachineName; } catch { machine_name = "Unknown"; }

            //build query and append to the query list
            string sql;
            sql = "INSERT INTO raw_events ( level, level_string, time_logged, time_captured, machine_name, source, event_id, event_string, event_xml ) VALUES( '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}' );";
            try { sql_queries.Add(String.Format(sql, level, level_string, time_logged, time_captured, machine_name, source, event_id, event_string, event_xml)); }
            catch
            {
                logger.log(String.Format("{0} - Failed to queue SQL INSERT!", thisMethod));
                EventSQLAgent.lost_events += 1;
            }
        }
    }

    public partial class EventSQLAgent : ServiceBase
    {
         // tuning vars
        private static int sql_hwm = 1000;//            normally 2000
        private static int sql_lwm = 250;//             normally 500
        private static int classifier_hwm = 1000;//     normally 2000

        // a queue object in which to buffer events
        private static readonly ConcurrentQueue<Alert> alert_queue = new ConcurrentQueue<Alert>();
        private static readonly ConcurrentQueue<EventRecord> classifier_queue = new ConcurrentQueue<EventRecord>();
        private static readonly ConcurrentQueue<string> sql_queue = new ConcurrentQueue<string>();

        // public "we're going down" var for threads to check and exit based on
        public static Int32 DIE_NOW_MOTHERFUCKERS = 0;
        public static Int32 AND_YOUR_KIDS_TOO = 0;

        // accounting variables - 32-bit int reads and writes are atomic, AKA thread-safe, since clobbering is a concern in this application
        public static Int32 sql_db_time_ms = 0;
        public static Int32 sql_classifier_time_ms = 0;
        public static Int32 lost_events = 0;
        public static Int32 lost_alerts = 0;
        public static Int32 transmitted_alerts = 0;
        public static Int32 blocked_events = 0;

        // thread handles
        private static Thread MainThreadH;
        private static Thread PerfThreadH;
        private static Thread SQLThreadH;
        private static Thread ClassifierThreadH;
        private static Thread AlertThreadH;

        // Performance tracking thread.  Sends data to graphite.
        private static void PerfThread()
        {
            // logging
            StreamWriter logh = File.AppendText(@"C:\Program Files\EventSQLizer\perf.log");
            Logger logger = new Logger(logh);
            logger.log("Started!");

            // break out the graphite hosts into a list
            string graphite_hosts_raw = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Exigent\EventSQLizer\Metrics", @"Destinations", @"Nothing");
            List<RemoteHost> graphite_hosts = new List<RemoteHost>();
            foreach(string cluster in graphite_hosts_raw.Split(','))
                {
                RemoteHost host = new RemoteHost(cluster.Split(':')[0], Convert.ToInt32(cluster.Split(':')[1]));
                graphite_hosts.Add(host);
                }

            // open the socket
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            Stopwatch sw = new Stopwatch();

            // get the local machine hostname
            string computername;
            try
            {
                computername = System.Net.Dns.GetHostName();
            }
            catch(Exception ex)
            {
                logger.log(String.Format("Could not get local system hostname!\n\n '{0}'\n\n", ex.ToString()));
                computername = "Unknown";
            }

            // the loop
            while (true)
            {
                // die if it's time to.
                if (AND_YOUR_KIDS_TOO == 1)
                {
                    logger.log("Dying on cue.");
                    logh.Close();
                    return;
                }

                // start the clock and get the current time
                sw.Start();
                Int64 timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                // a very very broad try/catch.  It's very important to stay out of the damn way.
                try
                {
                    // build the metric
                    string metrics;
                    metrics = String.Format("esi.rctc.wec_agent.{0}.perf.sql_ms {1} {2}\n", computername, sql_db_time_ms / 5, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.sql_classifier_time_ms {1} {2}\n", computername, sql_classifier_time_ms / 5, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.sql_queue_size {1} {2}\n", computername, sql_queue.Count, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.classifier_queue_size {1} {2}\n", computername, classifier_queue.Count, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.lost_events {1} {2}\n", computername, lost_events, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.blocked_events {1} {2}\n", computername, blocked_events, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.sql_queue_lwm {1} {2}\n", computername, sql_lwm, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.sql_queue_hwm {1} {2}\n", computername, sql_hwm, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.classifier_queue_hwm {1} {2}\n", computername, classifier_hwm, timestamp);
                    metrics += String.Format("esi.rctc.wec_agent.{0}.perf.transmitted_alerts {1} {2}\n", computername, transmitted_alerts, timestamp);

                    // reset values
                    sql_db_time_ms = 0;
                    sql_classifier_time_ms = 0;
                    transmitted_alerts = 0;

                    // send
                    byte[] send_buffer = Encoding.ASCII.GetBytes(metrics);
                    foreach (RemoteHost host in graphite_hosts)
                    {
                        try
                        {
                            IPAddress serverAddr = Dns.GetHostAddresses(host.hostname)[0];// i'm assuming that the local DNS cache will hide my shame here.
                            IPEndPoint endPoint = new IPEndPoint(serverAddr, host.port);
                            sock.SendTo(send_buffer, endPoint);
                        }
                        catch
                        {
                            logger.log(String.Format("Failed to send data to the graphite server {0}:{1}!", host.hostname, host.port));
                            continue;
                        }
                        
                    }
                }
                catch(Exception ex)
                {
                    logger.log(String.Format("Unable to build performance metric string!\n\n'{0}'\\n\n", ex.ToString()));
                    continue;
                }

                // sleep the appropriate amount based on how long collection and transmission took
                int timeremaining = 5000 - (int)sw.ElapsedMilliseconds;
                if (timeremaining > 0) System.Threading.Thread.Sleep(timeremaining);
                sw.Restart();
            }

        }

        // Thread for classifying events
        private static void ClassifierThread()
        {
            // logging
            StreamWriter logh = File.AppendText(@"C:\Program Files\EventSQLizer\classifier.log");
            Logger logger = new Logger(logh);
            logger.log("Started!");

            // loop.
            Stopwatch handler_sw = new Stopwatch();
            while (true)
            {
                // die if it's time to.
                if (AND_YOUR_KIDS_TOO == 1)
                {
                    logger.log("Dying on cue.");
                    logh.Close();
                    return;
                }

                EventRecord e;
                try
                {
                    while (classifier_queue.TryDequeue(out e) == false)
                        Thread.Sleep(100);
                }
                catch (Exception ex)
                {
                    logger.log(String.Format("Couldn't dequeue event!  Reason: {0}", ex.ToString()));
                    continue;
                }

                // hand off the event to the classifier to generate SQL queries
                // also timekeeping :D
                handler_sw.Restart();
                EventClassifier classifier = new EventClassifier(logger, e);
                sql_classifier_time_ms += (Int32)handler_sw.ElapsedMilliseconds;

                //account for queries blocked by the classifier
                if (classifier.event_blocked)
                    blocked_events += 1;

                // pass the generated queries to sql_queue
                foreach (string query in classifier.sql_queries)
                {
                    try { sql_queue.Enqueue(query); }
                    catch { logger.log("Could not enqueue SQL query from Classifier!"); }
                }

                // pass any generated alerts to the alert queue
                foreach (Alert alert in classifier.alerts)
                {
                    try { alert_queue.Enqueue(alert); }
                    catch { logger.log("Could not enqueue Alert from Classifier!"); }
                }
                    
                // Measured pace, unless things are CRAZY
                if (classifier_queue.Count < classifier_hwm)
                    Thread.Sleep(20);
            }
        }

        // thread to commit events to SQL
        private static void SQLThread()
        {
            // logging
            StreamWriter logh = File.AppendText(@"C:\Program Files\EventSQLizer\sql.log");
            Logger logger = new Logger(logh);
            logger.log("Started!");

            // instrumentation
            Stopwatch sql_sw = new Stopwatch();

            // DB setup
            // Fetch config from the registry
            string datasource = (string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Exigent\EventSQLizer\DB", @"DataSourceName", @"Nothing");
            string userid = (string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Exigent\EventSQLizer\DB", @"UserID", @"Nothing");
            string password = (string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Exigent\EventSQLizer\DB", @"Password", @"Nothing");
            string database = (string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Exigent\EventSQLizer\DB", @"DatabaseName", @"Nothing");

            // build connection string and connect
            SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder
            {
                DataSource = datasource,
                UserID = userid,
                Password = password,
                InitialCatalog = database
            };
            SqlConnection connection = new SqlConnection(builder.ConnectionString);

            // connect
            try
            {
                connection.Open();
                logger.log("Database connected!");
            }
            catch
            {
                logger.log("Couldn't connect to SQL database!");
                logh.Close();
                return;
            }

            // loop.
            while (true && AND_YOUR_KIDS_TOO == 0)
            {
                // create megaquery string, and insert count tracking var
                string megaquery = "";
                int insert_count = 0;

                // keep going until we cross the lwm
                while (sql_queue.Count > 0)
                {
                    // die if it's time to.
                    if (AND_YOUR_KIDS_TOO == 1)
                        logger.log("Time to die, flushing queue.");

                    // dequeue a query
                    string query;
                    try
                    {
                        while (sql_queue.TryDequeue(out query) == false)
                            Thread.Sleep(100);
                    }
                    catch (Exception ex)
                    {
                        logger.log(String.Format("Couldn't dequeue query!  Reason: {0}", ex.ToString()));
                        continue;
                    }

                    // glom queries together into batches
                    megaquery = String.Format("{0} {1}\n", megaquery, query);

                    // if we're over the limit, dump a load into SQL
                    if (insert_count > 30)
                    {
                        try
                        {
                            SqlCommand command = new SqlCommand(megaquery, connection);
                            sql_sw.Restart();
                            command.ExecuteNonQuery();
                            sql_db_time_ms += (Int32)sql_sw.ElapsedMilliseconds;
                        }
                        catch(System.InvalidOperationException)
                        {
                            logger.log(String.Format("Database connectivity failure!  Lost {0} INSERTs.", insert_count));
                            lost_events += insert_count;
                            logh.Close();
                            return;
                        }
                        catch (System.Data.SqlClient.SqlException ex)
                        {
                            bool connfail = false;
                            foreach(SqlError error in ex.Errors)
                            {
                                // class 17 and above are not syntax errors, but low-level errors, see the two links below.  Class 11 technically can be regular long-running query timeouts, but we'll consider those restartable.
                                // https://stackoverflow.com/questions/24041062/know-when-to-retry-or-fail-when-calling-sql-server-from-c?noredirect=1&lq=1
                                // https://docs.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-error-severities?view=sql-server-2014&redirectedfrom=MSDN
                                if (ex.Class >= 17 || ex.Class == 11)
                                    connfail = true;
                            }
                            if (connfail)
                            {
                                logger.log(String.Format("Database connectivity failure!  Lost {0} INSERTs.", insert_count));
                                lost_events += insert_count;
                                logh.Close();
                                return;
                            }
                            else
                            {
                                logger.log(String.Format("Query error {0}!\n\n'{1}'\n\n", ex.Class, ex.ToString()));
                                lost_events += insert_count;
                                logh.Close();
                                return;
                            }
                        }
                        catch (Exception ex)
                        {
                            logger.log(String.Format("SQL query failed!\n\n'{0}'\n\n", ex.ToString()));
                            lost_events += insert_count;
                        }
                        megaquery = "";
                        insert_count = 0;
                    }
                    insert_count++;
                    /**/
                    // if we're below the high water mark, insert a sleep to reduce CPU spikage
                    if (sql_queue.Count < sql_hwm)
                        Thread.Sleep(50);
                    // if we're below the low water mark, sleep even more aggressively.
                    if (sql_queue.Count < sql_lwm)
                        Thread.Sleep(25);
                    /**/

                }
            }
            logger.log("Dying on cue.");
            logh.Close();
            return;
        }

        // thread to raise alerts
        private static void AlertThread()
        {
            // tools
            HttpClient HttpClient = new HttpClient();

            // logging
            StreamWriter logh = File.AppendText(@"C:\Program Files\EventSQLizer\alert.log");
            Logger logger = new Logger(logh);
            logger.log("Started!");

            // get config
            string nagios_hosts_raw = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Exigent\EventSQLizer\Alerting", @"Destinations", @"Nothing");
            List<RemoteHost> nagios_hosts = new List<RemoteHost>();
            foreach (string cluster in nagios_hosts_raw.Split(','))
                {
                RemoteHost host = new RemoteHost(cluster.Split(':')[0], Convert.ToInt32(cluster.Split(':')[1]));
                nagios_hosts.Add(host);
                }

            // loop.
            List<Alert> alert_list = new List<Alert>();
            int minute_start = DateTime.Now.Minute;
            int max_alert_lines = 150;
            while (true && AND_YOUR_KIDS_TOO == 0)
            {
                // don't hog the core.
                Thread.Sleep(1000);

                foreach (RemoteHost host in nagios_hosts)
                    {
                    // send the "all clear" so nagios knows we're alive
                    try
                        {
                        NagiosAlert nagalert = new NagiosAlert(0, @"All clear.");
                        StringContent content = new StringContent(JsonConvert.SerializeObject(nagalert));
                        HttpClient.PostAsync(String.Format("https://{0}:{1}", host.hostname, host.port), content);
                        }
                    catch (Exception ex)
                        {
                        logger.log(String.Format("Error constructing alert JSON!\n\n'{0}'\n\n", ex.ToString()));
                        }

                    // dump all the alerts we have
                    int alert_status = 0;
                    string alert_string = "";
                    while (alert_queue.Count > 0 && alert_list.Count <= max_alert_lines)
                        {
                        // die if it's time to.
                        if (AND_YOUR_KIDS_TOO == 1)
                            {
                            logger.log("Time to die, flushing the queue.");
                            break;
                            }

                        // dequeue an alert
                        Alert alert;
                        try
                            {
                            while (alert_queue.TryDequeue(out alert) == false)
                                Thread.Sleep(100);
                            alert_list.Add(alert);
                            }
                        catch (Exception)
                            {
                            logger.log("Failed to dequeue alert!!");
                            EventSQLAgent.lost_alerts += 1;
                            continue;
                            }
                        }

                    // if it's been a minute since we last sent an alert, map our internal alert onto a nagios alert and send
                    if (minute_start != DateTime.Now.Minute || alert_list.Count > max_alert_lines)
                        {
                        if (alert_list.Count > 0)
                            {
                            logger.log(String.Format("Transmitting {0} alerts!{1}", alert_list.Count, alert_string.Replace("\\n", "\n\t")));// update the minute tracker

                            // stats
                            transmitted_alerts += alert_list.Count;

                            minute_start = DateTime.Now.Minute;

                            // glom into one message
                            foreach (Alert a in alert_list)
                                {
                                if (a.severity > alert_status)
                                    alert_status = a.severity;
                                alert_string += "\\n";
                                alert_string += a.text;
                                }

                            // Transmit
                            try
                                {
                                NagiosAlert nagalert = new NagiosAlert(alert_status, String.Format("{0} alerts!{1}\n", alert_list.Count, alert_string));
                                StringContent content = new StringContent(JsonConvert.SerializeObject(nagalert));
                                HttpClient.PostAsync(String.Format("https://{0}:{1}", host.hostname, host.port), content);
                                }
                            catch (Exception ex)
                                {
                                logger.log(String.Format("Failed to post alert to Nagios JSON host {0}:{1} !\n\n'{2}'\n\n", ex.ToString(), host.hostname, host.port));
                                }

                            // clear out the alert list
                            alert_list.Clear();
                            }
                        }
                    }
            }
            logger.log("Dying on cue.");
            logh.Close();
            return;
        }

        // main thread, creates all the other subthreads
        private static void MainThread()
        {
            // logfiles defined
            // try to hook all logs, starting with "ForwardedEvents".  If "ForwardedEvents" is available,
            // assume that this machine is a WEC and skip hooking any others
            // ForwardedEvents MUST BE FIRST ON THE LIST ~~!~!!!~!!~1
            string[] eventlogs = { "ForwardedEvents", "Application", "Security", "System" };
            EventLogWatcher[] eventwatchers = new EventLogWatcher[eventlogs.Length];

            // open up log files
            StreamWriter logh = File.AppendText(@"C:\Program Files\EventSQLizer\eventsqlizer.log");
            Logger logger = new Logger(logh);
            logger.log("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");
            logger.log("EventSQLizer starting up.");

            // and the SQL thread
            SQLThreadH = new Thread(SQLThread);
            SQLThreadH.Start();
            logger.log("SQL thread started...");

            // and the Classifier Thread
            ClassifierThreadH = new Thread(ClassifierThread);
            ClassifierThreadH.Start();
            logger.log("Classifier thread started...");

            // Annnnd the perf thread
            PerfThreadH = new Thread(PerfThread);
            PerfThreadH.Start();
            logger.log("Performance thread started...");

            // and and and the alerting thread is back!
            AlertThreadH = new Thread(AlertThread);
            AlertThreadH.Start();
            logger.log("Alert thread started...");

            for (int i = 0; i < eventlogs.Length; i++)
            {
                logger.log(String.Format("Attempting to hook log '{0}'...", eventlogs[i]));
                try
                {
                    // special handling here.
                    if (eventlogs[i] == "ForwardedEvents")
                    {
                        // this is a very shitty way to handle this.  
                        if (System.Net.Dns.GetHostName().ToUpper().Contains("WEC"))
                        {
                            logger.log(String.Format("Caught the 'ForwardedEvents' log, skipping any further logs as this is a WEC server. (It has 'WEC' in its name."));
                            eventwatchers[i] = new EventLogWatcher(eventlogs[i]);
                            eventwatchers[i].EventRecordWritten += eventHook;
                            eventwatchers[i].Enabled = true;
                            break;
                        }
                        else
                        {
                            logger.log(String.Format("skipping, this server does not have WEC in its name."));
                            continue;// this is not a WEC, so we don't want forwarded events.
                        }
                    }

                    eventwatchers[i] = new EventLogWatcher(eventlogs[i]);
                    eventwatchers[i].EventRecordWritten += eventHook;
                    eventwatchers[i].Enabled = true;
                    logger.log(String.Format("succeeded!"));
                }
                catch
                {
                    logger.log(String.Format("failed!"));
                }
            }

            logger.log("EventSQLizer started!");

            // restart and log any threads that die.
            while (true)
            {
                // die on queue
                if (DIE_NOW_MOTHERFUCKERS == 1)
                {
                    logger.log("Dying on cue, telling subthreads to die as well.");
                    AND_YOUR_KIDS_TOO = 1;

                    // unhook events so the queues run dry
                    for (int i = 0; i < eventlogs.Length; i++)
                        eventwatchers[i].EventRecordWritten -= eventHook;

                    if (!ClassifierThreadH.Join(30000))
                        ClassifierThreadH.Abort();
                    if (!SQLThreadH.Join(30000))
                        SQLThreadH.Abort();
                    if (!AlertThreadH.Join(30000))
                        AlertThreadH.Abort();
                    if (!PerfThreadH.Join(30000))
                        PerfThreadH.Abort();

                    return;
                }

                if (SQLThreadH.Join(1000))
                {
                    logger.log("SQL thread died, restarting.");
                    SQLThreadH = null;
                    SQLThreadH = new Thread(SQLThread);
                    SQLThreadH.Start();
                }
                if (ClassifierThreadH.Join(1000))
                {
                    logger.log("Classifier thread died, restarting.");
                    ClassifierThreadH = null;
                    ClassifierThreadH = new Thread(SQLThread);
                    ClassifierThreadH.Start();
                }
                if (AlertThreadH.Join(1000))
                {
                    logger.log("Alert thread died, restarting.");
                    AlertThreadH = null;
                    AlertThreadH = new Thread(SQLThread);
                    AlertThreadH.Start();
                }
                if (PerfThreadH.Join(1000))
                {
                    logger.log("Perf thread died, restarting.");
                    PerfThreadH = null;
                    PerfThreadH = new Thread(SQLThread);
                    PerfThreadH.Start();
                }
            }


        }

        private static void eventHook(object source, EventRecordWrittenEventArgs e)
        {
            // enqueue event in classifier queue
            classifier_queue.Enqueue(e.EventRecord);
        }

        // service state stuff
        public enum ServiceState
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceStatus
        {
            public int dwServiceType;
            public ServiceState dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
        };

        // Dll import for setting service state
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(System.IntPtr handle, ref ServiceStatus serviceStatus);

        public EventSQLAgent()
        {
            InitializeComponent();
            ServiceStatus ss = new ServiceStatus();
            ss.dwCurrentState = ServiceState.SERVICE_STOPPED;
            SetServiceStatus(this.ServiceHandle, ref ss);
        }

        protected override void OnStart(string[] args)
        {
            StreamWriter logh = File.AppendText(@"C:\Program Files\EventSQLizer\service.log");
            Logger logger = new Logger(logh);
            logger.log("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");
            logger.log("EventSQLizer starting up.");

            // Report started
            ServiceStatus ss = new ServiceStatus();
            ss.dwCurrentState = ServiceState.SERVICE_RUNNING;
            SetServiceStatus(this.ServiceHandle, ref ss);
            logger.log("OnStart - Reported 'Running' to service control");

            // then start the main thread
            MainThreadH = new Thread(MainThread);
            MainThreadH.Start();
            logger.log("Main thread started...");
            logh.Close();
        }

        protected override void OnStop()
        {
            // open up log files
            StreamWriter logh = File.AppendText(@"C:\Program Files\EventSQLizer\service.log");
            Logger logger = new Logger(logh);

            logger.log("EventSQLizer shutting down...");

            // Report
            logger.log("EventSQLizer stopping...");
            ServiceStatus ss = new ServiceStatus();
            ss.dwCurrentState = ServiceState.SERVICE_STOP_PENDING;
            SetServiceStatus(this.ServiceHandle, ref ss);
            logger.log("Reported 'stop pending' to service controller.");

            // tell threads that we're dying, and execute them if they don't obey
            DIE_NOW_MOTHERFUCKERS = 1;
            MainThreadH.Join();

            // Report
            logger.log("EventSQLizer stopped.");
            ss.dwCurrentState = ServiceState.SERVICE_STOPPED;
            SetServiceStatus(this.ServiceHandle, ref ss);
            logger.log("Reported 'stopped' to service controller.");

            logh.Close();
            base.OnStop();
        }
    }
}