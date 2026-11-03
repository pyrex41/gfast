# Usability evaluation protocol

This is a planned study, not a claim that users have completed it.

Recruit five developers unfamiliar with gfast (record Go/API experience). Give each a clean checkout, supported Go, and the README. Record time, assistance, errors, and documentation lookups. Avoid teaching the solution during the task; record interventions when needed.

1. Create a JSON POST endpoint with two field constraints.
2. Protect it with a credential-verifying provider and return a documented rejection.
3. Test it with a provider override and assert the invalid-input response.
4. Add a multipart upload and identify its size limit.
5. Inspect OpenAPI and generate or manually implement a small client.

Primary provisional criterion (D01): at least four participants complete tasks 1–3 in 15 minutes without solution-level assistance. Secondary outcomes: error frequency, clarity of diagnostics, number of undocumented assumptions, and success on tasks 4–5. Compare with FastAPI/Huma only using counterbalanced task order and comparable prior experience.

Publish anonymized observations, task wording, framework versions and failures. Do not convert five participants into a population-wide usability claim. Turn repeated mistakes into documentation/API changes and repeat with new participants.
