# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CSIS_CLIENT_ID | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CSIS OAuth2 client ID. |
| CSIS_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CSIS OAuth2 client secret. |
| CONNECTOR_NAME | `string` |  | string | `"CSIS Cyber Data Feed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Indicator", "Malware", "Intrusion-Set"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT6H` for six hours). |
| CSIS_FEED_TYPES | `array` |  | `essential` `advanced` | `["advanced"]` | Comma-separated CSIS CDF feeds to ingest: `essential` (IOCs + malware) and/or `advanced` (IOCs + malware + threat category + threat actors). |
| CSIS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to every object this connector creates. |
| CSIS_MIN_CONFIDENCE_SCORE | `integer` |  | `0 <= x <= 100` | `0` | Minimum CSIS `confidence_score` (0-100) an IOC must have to be ingested. |
| CSIS_REQUEST_TIMEOUT_SECONDS | `integer` |  | `1 <= x ` | `60` | Timeout in seconds for each request to the CSIS API. |
