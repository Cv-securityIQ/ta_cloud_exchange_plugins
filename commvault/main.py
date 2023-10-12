import requests
from datetime import datetime, timedelta
import traceback
from urllib.parse import urlparse
import re
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
)

MAX_PAGE_SIZE = 100
MAX_PULL_PAGE_SIZE = 2000
PLUGIN_NAME = "CommVault CTE Plugin"
MAX_RETRY_COUNT = 4
TIME_OUT = 30
RE_DEL_HTML = re.compile(r"(<span[^>]*>(.+?)</span>)|(<.*?>)")
RE_GET_LINK = re.compile(r"<a[^>]*href=(.+?)>.+?</a>")
ANOMALOUS_EVENTCODE_STRINGS = {
    "7:333": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "14:337": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
}


COMMVAULT_TO_NETSCOPE_SEVERITY = {
    -1: SeverityType.UNKNOWN,
    0: SeverityType.LOW,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.LOW,
    4: SeverityType.HIGH,
    5: SeverityType.HIGH,
    6: SeverityType.HIGH,
    7: SeverityType.HIGH,
    8: SeverityType.CRITICAL,
    9: SeverityType.CRITICAL,
    10: SeverityType.CRITICAL,
}


class CommVaultPlugin(PluginBase):
    """The CommVault plugin implementation."""

    def _validate_url(self, url: str) -> bool:
        parsed = urlparse(url.strip())
        flag = (parsed.scheme.strip() != "") and (parsed.netloc.strip() != "")
        return flag

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        try:
            base_url = configuration["commandcenter_url"].strip().strip("/")
            headers = {
                "authToken": configuration["auth_token"],
                "Accept": "application/json",
            }
            response = requests.get(
                f"{base_url}/ApiToken/User",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            if response.status_code == 200:
                self.logger.info(
                    f"{PLUGIN_NAME}: Credentials validated successfully"
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                return ValidationResult(
                    success=False, message="Incorrect Credentials Provided."
                )
        except requests.ConnectionError as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False, message="Incorrect Credentials provided."
            )
        except Exception as ex:
            self.logger.error(str(ex))
            return ValidationResult(
                success=False,
                message=(
                    "Error occurred while validating configuration parameters."
                    " Check logs for more detail."
                ),
            )

    def handle_status_code(
        self,
        response,
        custom_message: str = None,
        plugin: str = None,
    ):
        """Handle status code of response.

        Args:
            response (response): response of API call
            error_code (str, optional): error code. Defaults to None.
            custom_message (str, optional): custom message to write. Defaults
            to None.
            plugin (str, optional): plugin name. Defaults to None.
        """
        custom_message_str = (
            (custom_message + ",") if custom_message is not None else ""
        )
        if response.status_code == 200 or response.status_code == 201:
            try:
                return response.json()
            except ValueError as err:
                error = (
                    f"{custom_message_str} Exception"
                    + " occurred while parsing JSON response."
                )
                if plugin:
                    error = f"{plugin}, {error}"
                self.logger.error(error, details=traceback.format_exc())
                raise err
        elif response.status_code == 401:
            self.logger.error(
                (
                    f"{plugin}, {custom_message_str} Received"
                    + " exit code 401, Authentication Error."
                ),
                details=response.text,
            )
        elif response.status_code == 403:
            self.logger.error(
                (
                    f"{custom_message_str} {plugin},"
                    + " Received exit code 403, Forbidden Error."
                ),
                details=response.text,
            )
        elif response.status_code == 429:
            self.logger.error(
                (
                    f"{custom_message_str} {plugin},"
                    + " Received exit code 429, Too many requests."
                ),
                details=response.text,
            )
        elif response.status_code == 409:
            self.logger.error(
                (
                    f"{custom_message_str} {plugin},"
                    " Received exit code 409, Concurrency found while calling"
                    " the API."
                ),
                details=response.text,
            )
        elif response.status_code >= 400 and response.status_code < 500:
            self.logger.error(
                (
                    f"{plugin},"
                    f" {custom_message_str} Received"
                    f" exit code {response.status_code}, HTTP client Error."
                ),
                details=response.text,
            )
        elif response.status_code >= 500 and response.status_code < 600:
            self.logger.error(
                (
                    f"{plugin},"
                    f" {custom_message_str} Received"
                    f" exit code {response.status_code}, HTTP server Error."
                ),
                details=response.text,
            )
        response.raise_for_status()

    def fetch_events(self, from_time: datetime = None) -> tuple:
        """
        Fetches the events from Commvault REST API from from_time onwards
        """
        base_url = self.configuration["commandcenter_url"].strip().strip("/")
        params = {
            "level": 10,
            "showAnomalous": True,
        }
        if from_time and isinstance(from_time, datetime):
            params["fromTime"] = str(int(from_time.timestamp()))
        response = requests.get(
            f"{base_url}/Events",
            params=params,
            headers=self._get_headers(),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        response = self.handle_status_code(
            response,
            "Error occurred while pulling indicators",
            PLUGIN_NAME,
        )

        if not response.get("commservEvents"):
            self.logger.info(
                f"{PLUGIN_NAME}: No new events from {str(from_time)}"
            )
            return []

        events = response.get("commservEvents")
        events = [
            d
            for d in events
            if d.get("eventCodeString") in ANOMALOUS_EVENTCODE_STRINGS
        ]
        events = sorted(events, key=lambda d: d.get("timeSource"))
        for event in events:
            try:
                client_id = event.get("clientEntity").get("clientId")
                client_hostname = self.get_client_hostname(client_id)
                event["client_hostname"] = client_hostname
            except KeyError:
                pass

        return events

    def get_client_hostname(self, client_id: int) -> str:
        "Get the hostname from client properties using client id"
        base_url = self.configuration["commandcenter_url"].strip().strip("/")
        response = requests.get(
            f"{base_url}/Client/{int(client_id)}",
            params={},
            headers=self._get_headers(),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        response = self.handle_status_code(
            response,
            "Error occurred in get_client_hostname()",
            PLUGIN_NAME,
        )
        hostname = ""
        try:
            hostname = response["clientProperties"][0]["client"][
                "clientEntity"
            ]["hostName"]
        except KeyError as e:
            self.logger.error(
                f"Exception while getting client hostname: {str(e)}"
            )
        return hostname

    def pull(self):
        """Pull indicators from CommVault."""
        try:
            indicators = []
            base_url = self.configuration["commandcenter_url"]
            self.logger.info(
                f"{PLUGIN_NAME}: Pulling indicators from {base_url} "
            )
            if not self.last_run_at:
                from_time = datetime.now() - timedelta(
                    days=int(self.configuration["days"])
                )
                self.logger.info(
                    f"{PLUGIN_NAME}: will run for the first time"
                    + f" and pull events from: {str(from_time)}"
                )
            else:
                from_time = self.last_run_at
                self.logger.info(
                    f"{PLUGIN_NAME}: Pulling events"
                    + f" from timestamp: {str(from_time)}"
                )
            events = self.fetch_events(from_time)
            if events and len(events) > 0:
                for event in events:
                    detectedTime = datetime.fromtimestamp(
                        int(event.get("timeSource"))
                    )
                    event_desc = event.get("description", "")
                    event_code = event.get("eventCodeString")
                    re_extended_info = ANOMALOUS_EVENTCODE_STRINGS[
                        event_code
                    ].get("extended_info")
                    re_comments = ANOMALOUS_EVENTCODE_STRINGS[event_code].get(
                        "comments"
                    )
                    if len(re_extended_info.findall(event_desc)) > 0:
                        self.logger.info(
                            f"re_extended_info.findall(event_desc):"
                            + f"{re_extended_info.findall(event_desc)}"
                        )
                        extended_info = (
                            re_extended_info.findall(event_desc)[0]
                            .strip()
                            .strip('"')
                            .strip('"')
                        )
                    else:
                        extended_info = ""
                    comments = re_comments.sub(
                        "", event.get("description", "")
                    )
                    comments = " ".join(comments.split())
                    comments = re.sub('Please click here for more details.',
                                      '', comments, flags=re.I)
                    indicators.append(
                        Indicator(
                            value=event.get("client_hostname"),
                            type=IndicatorType.URL,
                            firstSeen=detectedTime,
                            lastSeen=detectedTime,
                            severity=COMMVAULT_TO_NETSCOPE_SEVERITY.get(
                                event.get("severity"), -1
                            ),
                            tags=[],
                            comments=comments,
                            extendedInformation=extended_info,
                        )
                    )

        except Exception as err:
            self.logger.error(
                (
                    f"{PLUGIN_NAME}: Error occured while pulling indicators,"
                    f" {err}"
                ),
                details=traceback.format_exc(),
            )
            raise err
        return indicators

    def push(self, indicators, action_dict) -> PushResult:
        """Push indicators to CommVault."""
        try:

            action_dict = action_dict.get("parameters", {})
            self.logger.info(
                f"{PLUGIN_NAME}: Pushing indicators started at:"
                + f"{str(datetime.now())}"
            )
            # build the body
            alerts = []
            for indicator in indicators:
                if indicator.type == IndicatorType.MD5:
                    alerts.append(dict(indicator))
                self.logger.info(
                    f"{PLUGIN_NAME}: Received alert from Cloud Exchange: "
                    + f"{str(indicator)}"
                )
        except Exception as e:
            return PushResult(
                success=False,
                message=f"Could not push to CommVault. Exception: {str(e)}.",
            )

        return PushResult(
            success=True,
            message=f"Pushed indicators successfully to CommVault",
        )

    def _get_headers(self) -> dict:
        """Get common headers."""
        headers = {
            "AuthToken": self.configuration["auth_token"],
            "Accept": "application/json",
        }
        return headers

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "commandcenter_url" not in configuration
            or not configuration["commandcenter_url"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: No commandcenter_url key found in the"
                f" configuration parameters."
            )
            return ValidationResult(
                success=False,
                message=(
                    f"Command Center URL can not be empty."
                    + f" Supplied Command Center URL:"
                    f" {configuration['commandcenter_url']}"
                ),
            )
        if not self._validate_url(configuration["commandcenter_url"]):
            self.logger.error(
                f"{PLUGIN_NAME}: Invalid Command Center URL found in the"
                " configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Command Center URL provided."
            )
        if "auth_token" not in configuration:
            self.logger.error(
                f"{PLUGIN_NAME}: No auth_token key found in the configuration"
                " parameters."
            )
            return ValidationResult(
                success=False, message="Authentication Token can not be empty."
            )
        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    f"{PLUGIN_NAME}: Validation error occured Error: Invalid"
                    " days provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Number of days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Number of days provided.",
            )

        self.logger.debug(f"{PLUGIN_NAME}: Reached end of validate")
        return self._validate_credentials(configuration)

    def get_actions(self):
        """Get available actions."""
        return [
            Action(
                label="Disable data aging on subclient",
                value="block_subclient_by_ip_address",
            ),
            Action(
                label="Add to Virus Definition",
                value="add_to_virus_definition",
            ),
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration."""
        if action.value not in [
            "block_subclient_by_ip_address",
            "add_to_virus_definition",
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action.parameters.get("plan_name") is None:
            return ValidationResult(
                success=False, message="Plan Name should not be empty."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value in [
            "block_subclient_by_ip_address",
            "add_to_virus_definition",
        ]:
            return [
                {
                    "label": "Plan Name",
                    "key": "plan_name",
                    "type": "text",
                    "default": "CommVault Plan Name",
                    "mandatory": True,
                    "description": (
                        "Name of CommVault Data Classification Plan where"
                        + " indicator should be pushed."
                    ),
                },
            ]
