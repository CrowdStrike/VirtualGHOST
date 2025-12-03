#!/usr/bin/env python3
"""
Description: VirtualGHOST and general sophisticated threat actor detection script for vSphere environments
Author: CrowdStrike
Acknowledgements: Heavily inspired by the great work from the community at https://github.com/vmware/pyvmomi-community-samples/
"""
import argparse
import getpass
import logging
import os
import re
import shutil
import socket
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from urllib.parse import quote

import requests
from pyVim.connect import SmartConnect
from pyVmomi import vim


def setup_logging(log_level, log_file: Path) -> logging.Logger:
    """Configure logging based on specified level and return a logger object."""
    # Setup custom level numbers
    ALERT_LEVEL = 35  # Between WARNING (30) and ERROR (40)
    IMPORTANT_LEVEL = 25  # Between INFO (20) and WARNING (30)

    # Register the new levels with names
    logging.addLevelName(ALERT_LEVEL, "ALERT")
    logging.addLevelName(IMPORTANT_LEVEL, "IMPORTANT")

    def alert(self, message, *args, **kwargs):
        """Log 'msg % args' with severity 'ALERT'."""
        self._log(ALERT_LEVEL, message, args, **kwargs)

    def important(self, message, *args, **kwargs):
        self.log(IMPORTANT_LEVEL, message, *args, **kwargs)

    # Attach methods to the Logger class
    logging.Logger.alert = alert
    logging.Logger.important = important

    logger = logging.getLogger()
    logger.setLevel(log_level)

    # TODO: Adjust this so we can provide an extra= dictionary argument & display it
    formatter = logging.Formatter(
        "%(asctime)s UTC | %(levelname)s | %(funcName)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime  # Use UTC

    # File logger setup
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Also stream to standard out
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def search_datastore_for_logfiles(
    datastore: vim.Datastore,
    logger: logging.Logger,
) -> List[vim.host.DatastoreBrowser.SearchResults]:
    """Search a given vSphere datastore for all VMware VM log files."""
    logger.debug(f"[+] Searching datastore '{datastore.name}' for log files")
    base_path = f"[{datastore.name}]"
    search_spec = vim.host.DatastoreBrowser.SearchSpec()
    search_spec.matchPattern = ["vmware*.log"]
    logger.debug(f"[+] Using match pattern: {search_spec.matchPattern}")
    search_spec.details = vim.host.DatastoreBrowser.FileInfo.Details(
        fileSize=True,
        modification=True,
    )
    browser = datastore.browser
    logger.debug(f"[+] Creating search task for datastore '{datastore.name}'")
    start_time = time.time()

    try:
        task = browser.SearchSubFolders(base_path, search_spec)
        results = wait_task(task, logger)
        search_duration = time.time() - start_time
        logger.debug(
            f"[+] Search complete for datastore '{datastore.name}' in {search_duration:.2f}s"
        )
        if results:
            logger.debug(
                f"[+] Found {len(results) if isinstance(results, list) else 1} result folders"
            )
            return results
        else:
            logger.debug(f"[!] No results found in datastore '{datastore.name}'")
            return None
    except vim.fault.InaccessibleDatastore as e:
        logger.error(f"[!] Datastore '{datastore.name}' is inaccessible: {str(e)}")
        return None
    except vim.fault.InvalidDatastore as e:
        logger.error(f"[!] Datastore '{datastore.name}' is invalid: {str(e)}")
        return None
    except vim.fault.NoPermission as e:
        logger.error(
            f"[!] No permission to access datastore '{datastore.name}': {str(e)}"
        )
        return None
    except vim.fault.FileFault as e:
        logger.error(
            f"[!] File fault when searching datastore '{datastore.name}': {str(e)}"
        )
        return None
    except Exception as e:
        logger.error(
            f"[!] Unexpected error when searching datastore '{datastore.name}': {str(e)}"
        )
        return None


def get_vsphere_cookie(si: SmartConnect, logger: logging.Logger) -> Dict[str, str]:
    """Create a vSphere session cookie string from the SmartConnect cookie data."""
    logger.info("[+] Retrieving vSphere session cookie")
    # Get the cookie built from the current session
    client_cookie = si._stub.cookie

    # Break apart the cookie into its component parts. This is more than
    # is needed, but a good example of how to break apart the cookie
    # anyways. The verbosity makes it clear what is happening.
    cookie_name = client_cookie.split("=", 1)[0]
    cookie_value = client_cookie.split("=", 1)[1].split(";", 1)[0]
    cookie_path = (
        client_cookie.split("=", 1)[1].split(";", 1)[1].split(";", 1)[0].lstrip()
    )
    cookie_text = f" {cookie_value}; ${cookie_path}"

    # Make a cookie
    cookie = {cookie_name: cookie_text}

    logger.debug(f"[+] Session cookie name: {cookie_name}")
    logger.info("[+] Cookie retrieved successfully")

    return cookie


def generate_individual_files(
    search_results: vim.host.DatastoreBrowser.SearchResults,
    datacenter: vim.Datacenter,
    logger: logging.Logger,
) -> List[dict]:
    """Given a list of datastore search hits, generate a list of dictionaries with the necessary
    information to download the files parsed out.

    Args:
        search_results (vim.host.DatastoreBrowser.SearchResults): Search hits

    Returns:
        List[dict]: Individual file records
    """
    logger.debug(f"[+] Processing search results for {search_results.folderPath}")
    file_records = []

    # Pattern to match [datastore] path/format
    pattern = rf"\[?({search_results.datastore.name})\]?\s+?(\S+?)$"

    match = re.search(pattern, search_results.folderPath)
    if match:
        datastore = match.group(1)  # Capture text inside brackets
        folder = match.group(2)  # Capture text after brackets and whitespace
        logger.debug(f"[+] Matched datastore path: [{datastore}] {folder}")
    else:
        logger.important(
            f"[-] Failed to match datastore path pattern for: {search_results.folderPath}. "
            "Files include: " + ", ".join([item.path for item in search_results.file])
        )
        return None

    file_count = len(search_results.file)
    if file_count:
        logger.debug(f"[+] Processing {file_count} files in this folder")

        for file in search_results.file:
            file_records.append(
                {
                    "datastore": datastore,
                    "folder": folder,
                    "filename": file.path,
                    "filesize": file.fileSize,
                    "modification": file.modification,
                    "datacenter": datacenter.name,
                }
            )
        logger.debug(f"[+] Generated {len(file_records)} file records")
    else:
        logger.debug("[+] Folder is empty, skipping...")

    return file_records


def get_hypervisors(
    content: vim.ServiceInstanceContent, logger: logging.Logger
) -> List[vim.HostSystem]:
    """Get a list of hypervisor (ESXi) hosts within the vSphere environment."""
    logger.debug("[+] Retrieving a list of ESXi hosts in the vSphere environment")
    host_view = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.HostSystem], True
    )
    hosts = list(host_view.view)
    logger.debug(f"[+] Retrieved {len(hosts)} hypervisor hosts")
    host_view.Destroy()
    return hosts


def wait_task(task: vim.Task, logger: logging.Logger) -> Optional[object]:
    """Wait for a long-running task to complete."""
    logger.debug(f"[+] Waiting for task '{task.info.descriptionId}' to complete")
    start_time = time.time()
    info: vim.TaskInfo = task.info

    while info.state in ["queued", "running"]:
        logger.info(
            f"... Still waiting for the task to complete. Current state: {info.state}."
        )
        time.sleep(5)
        info = task.info

    elapsed_time = time.time() - start_time
    logger.debug(
        f"[+] Task completed with state: {info.state} in {elapsed_time:.2f} seconds"
    )

    if info.state == "error":
        raise info.error

    return info.result


def get_vcenter_ip_addresses(
    content: vim.ServiceInstanceContent,
    logger: logging.Logger,
) -> Optional[List[str]]:
    """Get all IP addresses for a vCenter host."""
    try:
        hostname = get_vsphere_setting(content, "VirtualCenter.FQDN", logger)

        addr_info = socket.getaddrinfo(hostname, None)
        ip_addresses = list({info[4][0] for info in addr_info})
        logger.info(f"[+] All IP addresses for {hostname}: {ip_addresses}")

        return ip_addresses

    except socket.gaierror:
        logger.error(f"[-] Could not resolve hostname: {hostname}")
        return None
    except Exception as e:
        logger.error(f"[-] Unable to get vCenter IP addresses: {e}")
        return None


def get_interesting_events(
    service_instance: vim.ServiceInstanceContent,
    logger: logging.Logger,
) -> List[vim.event.Event]:
    """Get interesting events from vSphere Event API.

    Args:
        service_instance (vim.ServiceInstanceContent): Python object for accesessing vSphere APIs

    Returns:
        list[vim.event.Event]: List of events satisfying the 'interesting' criteria
    """
    logger.debug("[+] Starting event retrieval with filter")
    event_ids = [
        "esx.audit.ssh.session.closed",
        "esx.audit.ssh.session.opened",
        "esx.audit.ssh.enabled",
        "vim.event.VmOrphanedEvent",
        "vim.event.VmRemovedEvent",
        "vim.event.UserLoginSessionEvent",
    ]
    logger.debug(f"[+] Using event filter for event types: {event_ids}")

    event_filter_spec = vim.event.EventFilterSpec(eventTypeId=event_ids)

    start_time = time.time()
    event_collector = service_instance.eventManager.CreateCollectorForEvents(
        event_filter_spec
    )
    events_per_call = 1000
    logger.debug(f"[+] Retrieving first {events_per_call} events...")
    events = event_collector.ReadNextEvents(events_per_call)

    # Need to loop here because the default limit is 1000 and we dislike oddly round numbers
    while True:
        these_events = event_collector.ReadNextEvents(events_per_call)
        if len(these_events) == 0:
            logger.debug("[+] All events retrieved")
            event_collector.DestroyCollector()  # We'll be nice and try to save resources
            break
        logger.debug(f"[+] Retrieved a batch of {len(these_events)} events")
        events.extend(these_events)

    query_time = time.time() - start_time
    logger.debug(f"[+] Event query completed in {query_time:.2f} seconds")
    logger.info(f"[+] Retrieved {len(events)} events")

    event_types = Counter([type(item) for item in events])
    logger.info(f"[+] Event types found: {event_types}")
    logger.debug(
        f"[+] Stats for events filtered {Counter(item.fullFormattedMessage for item in events)}"
    )
    return events


def extract_event_data(
    events: List[vim.event.Event],
    fields_to_extract: List[Dict[str, str]],
    logger: logging.Logger,
):
    """Extract specified fields from a list of events, handling missing fields gracefully.

    Args:
        events (List[vim.event.Event]): List of vSphere events
        fields_to_extract (List[str]): Fields to extract from each event

    Returns:
        List[Dict[str, str]]: List of dictionaries with extracted fields
    """
    logger.debug(
        f"[+] Extracting {len(fields_to_extract)} fields from {len(events)} events"
    )
    results = []

    for event in events:
        event_data = {}
        event_id = getattr(event, "key", "unknown_event_id")

        for field in fields_to_extract:
            # Handle nested fields like 'host.name'
            if "." in field:
                parts = field.split(".")
                value = event
                try:
                    for part in parts:
                        if value is not None:
                            value = getattr(value, part, None)
                except Exception as e:
                    logger.debug(
                        f"Error extracting nested field '{field}' from event {event_id}: {e}"
                    )
                    value = None
            else:
                # Handle regular fields
                value = getattr(event, field, None)

            event_data[field] = value

        results.append(event_data)

    logger.debug(f"[+] Successfully extracted data from {len(results)} events")
    return results


def check_suspicious_environment_vars(
    log_line: str, logger: logging.Logger
) -> Dict[str, Dict[str, str]]:
    """Extract all environment variables from a log line and check which ones aren't allowed.

    Args:
        log_line (str): A log line containing environment variables

    Returns:
        Dict: Dictionary containing all_vars (all found variables) and suspicious_vars
              (disallowed ones)
    """
    # Extract environment variables in the format "NAME=VALUE"
    env_var_pattern = r'"([^="]+)=([^"]*)"'

    # Find all environment variables in the line
    all_vars = {}
    if "Environment:" in log_line:
        matches = re.finditer(env_var_pattern, log_line)
        for match in matches:
            var_name = match.group(1)
            var_value = match.group(2)
            all_vars[var_name] = var_value

    # Check which variables aren't in the allowed list
    allowed_env_vars = ["USER", "HOME", "PATH", "LANG", "SHELL", "LD_LIBRARY_PATH"]
    logger.debug(
        "[+] Performing environment variable check using allowed environment variables: "
        + ", ".join(allowed_env_vars)
    )
    suspicious_vars = {
        name: value for name, value in all_vars.items() if name not in allowed_env_vars
    }

    return {"all_vars": all_vars, "suspicious_vars": suspicious_vars}


def has_suspicious_environment_vars(log_line: str, logger: logging.Logger) -> bool:
    """Check if a log line contains suspicious environment variables.

    Args:
        log_line (str): A log line to check

    Returns:
        bool: True if suspicious variables found, False otherwise
    """
    if "Environment:" not in log_line:
        return False

    result = check_suspicious_environment_vars(log_line, logger)
    return len(result["suspicious_vars"]) > 0


def search_file_for_patterns(
    file_path: str,
    patterns: List[str],
    logger: logging.Logger,
) -> Dict[str, Union[int, List[str]]]:
    """Search a file for multiple regex patterns and print matching lines.

    Args:
        file_path (str): Path to the file to search
        patterns (List[str]): List of regex pattern strings

    Returns:
        dict: Dictionary with keys match_count and matched_lines
    """
    logger.debug(f"[+] Searching file '{file_path}' for {len(patterns)} patterns")
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    logger.debug(f"[+] File size: {file_size} bytes")

    # Compile all patterns for efficiency
    compiled_patterns = [re.compile(pattern) for pattern in patterns]
    line_num = 0
    match_count = 0
    matched_lines = []

    try:
        start_time = time.time()
        with open(file_path, "r") as file:
            for line_num, line in enumerate(file, 1):
                # Check if line has suspicious environment variables
                if "Environment:" in line and has_suspicious_environment_vars(
                    line, logger
                ):
                    matched_lines.append(f"Line {line_num}: {line.rstrip()}")
                    match_count += 1
                    logger.debug(
                        f"[+] Suspicious environment variables found in line {line_num}"
                    )
                    continue

                # Check other patterns
                for i, pattern in enumerate(compiled_patterns):
                    if pattern.search(line):
                        matched_lines.append(f"Line {line_num}: {line.rstrip()}")
                        match_count += 1
                        logger.debug(f"[+] Pattern {i} matched line {line_num}")
                        break
        search_duration = time.time() - start_time
        logger.debug(
            f"[+] Search completed in {search_duration:.2f}s, "
            f"found {match_count} matches in {line_num} lines"
        )
        return {"match_count": match_count, "matched_lines": matched_lines}

    except FileNotFoundError:
        logger.error(f"[-] Error: File '{file_path}' not found")
        return None
    except Exception as e:
        logger.error(f"[-] Error processing file: {e}", exc_info=True)
        return None


def search_log_file_for_ghosts(
    target_file: dict,
    si: SmartConnect,
    session: requests.Session,
    outdir: Path,
    logger: logging.Logger,
) -> bool:
    """Search a log file for evidence of a VirtualGHOST VM."""
    if target_file["folder"].endswith("/"):
        folder_filename = f"{target_file['folder']}{target_file['filename']}"
    else:
        folder_filename = f"{target_file['folder']}/{target_file['filename']}"

    logger.debug(
        f"[+] Examining log file: {folder_filename} "
        f"(size: {target_file.get('filesize', 'unknown')} bytes)"
    )
    indicators_found = False

    GHOST_PATTERNS = [
        r"/\.sdd",
        r"Command line:.+vmx\".+\"-x\"",
    ]

    logger.debug(
        f"[+] Using {len(GHOST_PATTERNS)} patterns plus environment variable checks for malicious "
        "activity detection"
    )

    start_time = time.time()
    with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as temp:
        # Download file
        url = f"https://{si._stub.host}/folder/{quote(folder_filename)}"
        logger.debug(f"[+] Downloading file from URL: {url}")
        try:
            logger.debug(
                "[+] Sending POST request with parameters: "
                f"dcPath={quote(target_file['datacenter'])}, dsName={quote(target_file['datastore'])}"
            )
            response = session.post(
                url,
                stream=True,
                params={
                    "dcPath": quote(target_file["datacenter"]),
                    "dsName": quote(target_file["datastore"]),
                },
            )
            response.raise_for_status()  # Raise exception for HTTP errors
            logger.debug(
                f"[+] Download request successful, status code: {response.status_code}"
            )

            # Write to temp file
            bytes_downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                temp.write(chunk)
                bytes_downloaded += len(chunk)
            temp.flush()
            temp.seek(0)
            tempfilename = temp.name
            download_time = time.time() - start_time
            logger.debug(
                f"[+] Download complete: {bytes_downloaded} bytes in {download_time:.2f}s "
                f"({bytes_downloaded/download_time:.2f} bytes/sec)"
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"[-] Error downloading file: {e}", exc_info=True)
            logger.warning(
                f"[-] Error context: URL={url}, "
                f"datacenter={target_file['datacenter']}, "
                f"datastore={target_file['datastore']}"
            )
            # Skipping the re-raise as we don't want to stop the scan if a single file fails
            # to download
            return False

    logger.debug(f"[+] Beginning scan of downloaded file: {tempfilename}")
    hits = search_file_for_patterns(tempfilename, GHOST_PATTERNS, logger)

    if hits and hits.get("match_count") >= 1:
        indicators_found = True  # Set the indicators found flag
        print("\n")
        logger.alert(
            f"Hits found in: {target_file['folder']}{target_file['filename']}"
        )
        for hit in hits["matched_lines"]:
            logger.alert(hit)

        # Copy the original file
        try:
            new_filename = outdir.joinpath(
                *[item for item in target_file["folder"].split("/") if item],
                target_file["filename"],
            )  # Unpacking with * so we get each folder from the datastore individually
            logger.debug(f"[+] Creating directory structure: {new_filename.parent}")
            new_filename.parent.mkdir(exist_ok=True)
            logger.debug(f"[+] Copying suspicious file to: {new_filename}")
            shutil.copy2(tempfilename, new_filename)
            logger.info(f"[+] Copied logfile to {new_filename}")
        except Exception as e:
            logger.error(f"[-] Error saving suspicious file: {e}", exc_info=True)
    else:
        logger.debug(
            f"[+] No indicators found in file: {target_file['folder']}{target_file['filename']}"
        )

    # Remove the temporary file
    try:
        logger.debug(f"[+] Removing temporary file: {tempfilename}")
        os.remove(tempfilename)
    except Exception as e:
        logger.important(f"[-] Failed to remove temporary file {tempfilename}: {e}")

    total_time = time.time() - start_time
    logger.debug(f"[+] File examination completed in {total_time:.2f}s")
    return indicators_found


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Python script developed by CrowdStrike Professional Services to access vSphere APIs "
            "and identify signs of potential compromise"
        )
    )

    # Required arguments
    parser.add_argument("-s", "--server", help="vCenter server hostname", required=True)
    parser.add_argument("-u", "--user", help="vSphere username", required=True)
    parser.add_argument("-p", "--password", help="vSphere password", default=None)

    # Optional arguments
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "IMPORTANT", "WARNING", "ALERT", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level",
    )
    parser.add_argument(
        "-d",
        "--no-ssl-check",
        dest="disable_ssl_verify",
        action="store_true",
        help="Disable SSL/TLS verification for HTTPS requests",
    )
    parser.add_argument(
        "--outdir",
        help="Directory to store output logs and messages. Defaults to the script directory.",
        default=Path(__file__).parent,
    )

    return parser.parse_args()


def get_vsphere_setting(
    service_instance: vim.ServiceInstanceContent,
    property_name: str,
    logger: logging.Logger,
) -> Union[str, float, None]:
    try:
        this_value = service_instance.setting.QueryView(property_name)[0].value
        return this_value
    except Exception as e:
        logger.debug(f"Unable to retrieve vSphere setting {property_name}. {e}")
        return None


def main():
    """Main function."""
    script_start_time = time.time()
    script_start_file_formatted = datetime.now().isoformat().replace(":", "")

    logger: logging.Logger = None
    logger_initialized = False  # Flag to track if logger has been initialized

    try:
        args = parse_arguments()

        output_dir = Path(args.outdir)
        output_dir.mkdir(exist_ok=True, parents=True)
        logger_debug_enabled = args.log_level == "DEBUG" or args.verbose

        # Prompt for password if not provided as argument
        password = args.password
        if password is None:
            password = getpass.getpass(
                f"Enter password for {args.user}@{args.server}: "
            )

        # Setup logging
        log_filename = output_dir.joinpath(
            f"CrowdStrike_GHOSTHUNTER_{args.server}_{script_start_file_formatted}.log"
        )
        logger = setup_logging(getattr(logging, args.log_level), log_filename)
        logger_initialized = True

        # Log script start with version and platform info
        logger.info(
            f"[+] GHOSTHUNTER starting execution at {datetime.now().isoformat()}"
        )
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Platform: {sys.platform}")
        logger.debug(f"Arguments: {args}")
        logger.debug(f"Output directory: {output_dir.absolute()}")

        # Connection phase
        logger.info(f"[+] Attempting connection to vCenter server {args.server}")
        logger.info(f"Using username: {args.user}")
        logger.debug(
            f"SSL verification: {'disabled' if args.disable_ssl_verify else 'enabled'}"
        )

        connection_start = time.time()
        si = SmartConnect(
            host=args.server,
            user=args.user,
            pwd=password,
            disableSslCertValidation=args.disable_ssl_verify,
        )
        connection_time = time.time() - connection_start
        logger.debug(f"[+] Connection established in {connection_time:.2f}s")
        logger.info(f"[+] Successfully connected to {args.server}")

        vsphere_service_content = si.RetrieveContent()
        logger.debug("Retrieved service content from vCenter server")

        # Collect data that's useful for scoping and general knowledge
        logger.info(
            f"vCenter version and build: "
            f"{vsphere_service_content.about.GetFullName()}"
            f" | OS Type: "
            f"{vsphere_service_content.about.GetOsType()}"
            f" | API Type: "
            f"{getattr(vsphere_service_content.about, 'apiType', None)}"
            f" | API Version: "
            f"{getattr(vsphere_service_content.about, 'apiVersion', None)}"
        )
        logger.info(
            f"Database retention settings: Events - "
            f"{get_vsphere_setting(vsphere_service_content, "event.maxAge", logger)}"
            f" | Tasks - "
            f"{get_vsphere_setting(vsphere_service_content, "task.maxAge", logger)}"
        )

        # Get all of the hypervisors in the environment. We'll use this object elsewhere a
        # few times.
        host_retrieval_start = time.time()
        all_hosts = get_hypervisors(vsphere_service_content, logger)
        host_retrieval_time = time.time() - host_retrieval_start
        logger.debug(f"[+] Host retrieval completed in {host_retrieval_time:.2f}s")
        logger.info(f"[+] Found {len(all_hosts)} ESXi hosts in the environment")

        # Setup a flag to indicate levels of concern that we need to alert the user about
        INDICATORS_FOUND = False
        NEEDS_REVIEW = False

        # Event searches
        logger.info("[+] Starting event search...\n")
        event_search_start = time.time()
        # all_events represent all of the events that we are going to review
        all_events = get_interesting_events(vsphere_service_content, logger)
        event_search_time = time.time() - event_search_start
        logger.debug(
            f"[+] Retrieved {len(all_events)} events in {event_search_time:.2f}s"
        )

        # Process events that were collected
        logger.debug("[+] Filtering events for vpxuser activity")
        vpxuser_events = [
            item for item in all_events if "vpxuser" in item.fullFormattedMessage
        ]

        logger.debug(
            "[+] Filtering events for activity originating from a vCenter IP address"
        )
        vcenter_ip_addresses = get_vcenter_ip_addresses(vsphere_service_content, logger)
        vcenter_events = []
        if vcenter_ip_addresses:
            vcenter_events = [
                item
                for item in all_events
                if any(ip in item.fullFormattedMessage for ip in vcenter_ip_addresses)
            ]

        remaining_events = [
            item
            for item in all_events
            if item not in vpxuser_events and item not in vcenter_events
        ]
        logger.debug(
            f"Found {len(vpxuser_events)} events referencing vpxuser, "
            f"{len(vcenter_events)} events originating from a vCenter IP, and "
            f"{len(remaining_events)} other events"
        )

        event_fields_to_display = [
            "createdTime",
            "userName",
            "host.name",
            "fullFormattedMessage",
            "eventTypeId",
            "objectName",
            "chainId",
        ]

        # Process vpxuser events (high severity)
        if vpxuser_events:
            INDICATORS_FOUND = True
            logger.debug("[+] Processing vpxuser events (high severity indicators)")
            print("\n")
            logger.alert(
                f"===== There were {len(vpxuser_events)} events involving the vpxuser account. "
                "These are NOT normal and are likely indications of Threat Actor activity. "
                "Specific instances will be displayed ====="
            )
            print("\n")
            extracted_events = extract_event_data(
                vpxuser_events, event_fields_to_display, logger
            )
            for event in extracted_events:
                event_string = " | ".join(
                    [
                        f"{key}: {value}"
                        for key, value in event.items()
                        if value is not None
                    ]
                )
                logger.alert(f"Event details: {event_string}")

        # Process SSH events involving vSphere IP (high severity)
        if vcenter_events:
            INDICATORS_FOUND = True
            logger.debug(
                "[+] Processing events involving a vCenter IP address (high severity indicators)"
            )
            print("\n")
            logger.alert(
                f"===== There were {len(vcenter_events)} events likely originating from a "
                "vCenter IP address. These are NOT normal and are likely indications of Threat "
                "Actor activity. Specific instances will be displayed ====="
            )
            print("\n")
            extracted_events = extract_event_data(
                vcenter_events, event_fields_to_display, logger
            )
            for event in extracted_events:
                event_string = " | ".join(
                    [
                        f"{key}: {value}"
                        for key, value in event.items()
                        if value is not None
                    ]
                )
                logger.alert(f"Event details: {event_string}")

        # Process other suspicious events (medium severity)
        if remaining_events:
            NEEDS_REVIEW = True
            logger.debug(
                "[+] Processing other suspicious events (medium severity indicators)"
            )
            print("\n")
            logger.warning(
                f"===== There were {len(all_events)} remaining events that are somewhat suspicious "
                "in nature. Statistics will be displayed for a quick triage. ====="
            )
            print("\n")
            event_stats = Counter(
                item.fullFormattedMessage for item in remaining_events
            )
            logger.warning(f"{event_stats}")
            print("\n")

        if all_events:
            event_filename = output_dir.joinpath(
                f"CrowdStrike_GHOSTHUNTER_ReviewedEvents_{script_start_file_formatted}.log"
            )
            all_event_printable = extract_event_data(
                all_events, event_fields_to_display, logger
            )
            with open(event_filename, "w") as f:
                for event in all_event_printable:
                    event_string = " | ".join(
                        [
                            f"{key}: {value}"
                            for key, value in event.items()
                            if value is not None
                        ]
                    )
                    f.write(event_string + "\n")
            logger.info(
                f"[+] Writing out a file containing each event reviewed to {event_filename}"
            )

        # Datastore searches
        logger.info(
            "Beginning the process of searching datastores for virtual machine log files & examining them for "
            "signs of suspicious activity."
        )
        targets = []

        # Get the list of all datacenters we have available to us
        logger.debug("[+] Retrieving datacenter list")
        datacenters_start = time.time()
        datacenters_object_view = (
            vsphere_service_content.viewManager.CreateContainerView(
                vsphere_service_content.rootFolder, [vim.Datacenter], True
            )
        )
        dc_count = len(datacenters_object_view.view)
        logger.info(f"Found {dc_count} datacenters")

        # List all the datastores
        total_datastores = 0
        for dc_idx, dc_obj in enumerate(datacenters_object_view.view, 1):
            logger.info(f"[+] Processing datacenter {dc_idx}/{dc_count}: {dc_obj.name}")
            temp_datastores = []
            datastores_object_view = (
                vsphere_service_content.viewManager.CreateContainerView(
                    dc_obj, [vim.Datastore], True
                )
            )
            ds_count = len(datastores_object_view.view)
            logger.info(f"Found {ds_count} datastores in datacenter {dc_obj.name}")
            total_datastores += ds_count

            for ds_obj in datastores_object_view.view:
                temp_datastores.append(ds_obj)
            # Add all of the datastores to the target object.
            # We need the datacenter information later.
            targets.append({"datacenter": dc_obj, "datastores": temp_datastores})
            datastores_object_view.Destroy()

        datacenters_time = time.time() - datacenters_start
        logger.info(
            f"[+] Datacenter and datastore enumeration completed in {datacenters_time:.2f}s"
        )
        logger.info(
            f"[+] Identified {total_datastores} datastores across {dc_count} datacenters"
        )

        # Clean up the views now that we have what we need
        datacenters_object_view.Destroy()

        # Virtual Machine logfile scanning
        files_to_scan = []
        logger.info("[+] Beginning scan for logfiles in datastores")
        scan_start_time = time.time()

        # Loop over the targets list. These represent a list of the datacenters and
        # associated datastores available
        for target_idx, target in enumerate(targets, 1):
            dc_name = target["datacenter"].name
            logger.debug(
                f"[+] Processing datacenter {target_idx}/{len(targets)}: {dc_name}"
            )

            for ds_idx, datastore in enumerate(target["datastores"], 1):
                logger.info(
                    f"[+] Scanning datastore {ds_idx}/{len(target['datastores'])}: "
                    f"{datastore.name} in datacenter {dc_name}"
                )
                # Build list of logfiles on the datastore
                logfiles = search_datastore_for_logfiles(datastore, logger)
                if logfiles:
                    logger.debug(
                        f"[+] Processing {len(logfiles) if isinstance(logfiles, list) else 1} "
                        "search results"
                    )
                    for search_result in logfiles:
                        # Break out the list of logfiles & create a list of files to scan
                        # (including the datacenter since we need that)
                        new_files = generate_individual_files(
                            search_result, target["datacenter"], logger
                        )
                        if new_files:
                            logger.info(
                                f"[+] Found {len(new_files)} log files to scan in {datastore.name}"
                            )
                            files_to_scan.extend(new_files)
                else:
                    logger.info(f"[+] No log files found in datastore {datastore.name}")

        scan_duration = time.time() - scan_start_time
        logger.info(
            f"[+] Log file discovery completed in {scan_duration:.2f}s, "
            f"found {len(files_to_scan)} files to scan"
        )
        if len(files_to_scan) == 0:
            logger.important(
                "[!] No log files identified on datastores. "
                "Ensure that datastores are accessible and consider re-executing this script"
            )

        # For each file to scan, call the search function & determine if there were any hits
        logger.info(
            f"[+] Scanning {len(files_to_scan)} log files for indicators of compromise"
        )
        files_with_hits = 0

        # Get a Requests Session object that we can reuse it rather than issuing numerous
        # individual requests for downloading files

        session = requests.Session()
        session.cookies.update(get_vsphere_cookie(si, logger))
        if args.disable_ssl_verify:
            session.verify = False
            logger.debug("[+] SSL certificate verification disabled for download")

            # Disable urllib3 certificate warnings
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning
            )

        for file_idx, log_file in enumerate(files_to_scan, 1):
            if (
                logger_debug_enabled and file_idx % 10 == 0
            ):  # Log progress every 10 files if in debug mode
                logger.debug(
                    f"Scanning file {file_idx}/{len(files_to_scan)} "
                    f"({(file_idx/len(files_to_scan)*100):.1f}%)"
                )

            logfile_ghost_scan_return = search_log_file_for_ghosts(
                log_file,
                si,
                session,
                output_dir,
                logger,
            )
            if logfile_ghost_scan_return:
                # If we had hits from the vmware logfile scan
                files_with_hits += 1
                INDICATORS_FOUND = True

        logger.info(
            f"Log file scanning complete. Found indicators in {files_with_hits} files"
        )

        # Provide the final message(s) to the user for their review
        script_duration = time.time() - script_start_time
        logger.info(f"GHOSTHUNTER execution completed in {script_duration:.2f} seconds")

        if INDICATORS_FOUND:
            print(
                "\a\n"
            )  # Generate a noise (where able) & add in a newline to make it extra obvious
            logger.alert(
                f"===== One or more indicators of potential compromise found. ====="
            )
            print("\n")
        if NEEDS_REVIEW:
            logger.alert(
                "===== One or more items of potential concern were identified. These items do "
                "not necessarily indicate a compromise, but should be investigated to ensure that "
                "there is a legitimate reason for them to have occurred. ====="
            )
        logger.info(
            f"[+] Please review the logfile that was generated at {log_filename} "
            "for additional details."
        )

        # Return success
        return 0

    except Exception as e:
        # Enhanced error reporting with context
        error_context = {
            "timestamp": datetime.now().isoformat(),
            "operation": sys._getframe().f_code.co_name,
        }

        # Add args context if available
        try:
            if "args" in locals():
                error_context.update(
                    {
                        "server": getattr(args, "server", "unknown"),
                        "user": getattr(args, "user", "unknown"),
                    }
                )
        except Exception:
            pass

        # Use logger if initialized, otherwise fall back to standard logging
        if logger_initialized:
            logger.error(f"[-] Error: {e}", exc_info=True)
            logger.error(f"[Error context: {error_context}")
        else:
            logging.error(f"[-] Error: {e}", exc_info=True)
            logging.error(f"Error context: {error_context}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
