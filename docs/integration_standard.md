# Pro-NDS Integration Standard

## 1. Purpose of Integrations
Integrations in Pro-NDS (Provenance Network Discovery System) serve as modular "Compliance Packs" or "Security Frameworks". They allow users to enable specific sets of security checks (e.g., CIS AWS, PCI-DSS, HIPAA) or third-party data sources (e.g., NVD, OSV) without bloating the core engine with irrelevant logic for every user.

## 2. Integration Architecture
An integration consists of three parts:
1.  **Metadata (Control Plane)**: define the integration's name, version, and pricing.
2.  **Logic (Discovery Engine)**: The actual code (Go/Python) that performs the scan or check.
3.  **Activation (Database)**: A `TenantFramework` record that links a tenant to an integration.

## 3. Standard Format (Metadata)
All integrations must be registered in `control_plane/app/routers/integrations.py` using the following JSON schema:

```json
{
    "id": "unique-kebab-case-id",
    "name": "Human Readable Name",
    "description": "Short description of what this integration provides.",
    "version": "1.0.0",
    "is_premium": false,
    "price_tier": "Free" // "Free", "Standard", "Enterprise"
}
```

### Naming Convention
-   **ID**: `vendor-product-version` (e.g., `cis-aws-1.5`, `pci-dss-3.2`)
-   **Name**: Title Case (e.g., `CIS AWS Foundations Benchmark`)
-   **Version**: Semantic Versioning (e.g., `1.5.0`)

## 4. Implementation Standard (Logic)
All compliance checks must be implemented in the `discovery_engine` (Go) to ensure performance.

### Location
`discovery_engine/internal/compliance/checks.go`

### Function Signature
```go
func CheckName(asset scanner.Asset) *Result
```

### Registration
Use the `RegisterCheck` function in `init()`:
```go
func init() {
    RegisterCheck("UNIQUE_Check_ID", CheckFunction)
}
```

## 5. Ensuring Stability (How to prevent breaking changes)
To ensure the app remains stable when adding new integrations:

1.  **Isolation**: Each integration's logic must be self-contained in its own function.
2.  **Graceful Failure**: Checks must return `nil` if they are not applicable to the asset type, rather than panicking.
3.  **Feature Flagging**: The `Evaluate` engine checks if the integration is enabled for the tenant before running the check (Coming in v1.1).
4.  **Versioning**: Always increment the version in metadata when changing logic.

## 6. Development Workflow
1.  **Add Metadata**: Update `AVAILABLE_FRAMEWORKS` in `control_plane/.../integrations.py`.
2.  **Add Logic**: Create a new check function in `discovery_engine/.../checks.go`.
3.  **Verify**: Restart the stack. The new integration will appear in the "Marketplace".
4.  **Test**: Enable it in the UI and run a scan.
