# LOC comparison

Expected total (whole repository): **4000** code lines; loc/ fixtures: **118**.

Included loc/ files (13): `loc/app/app.js`, `loc/app/service.py`, `loc/app/src/main/java/com/example/loc/Greeter.java`, `loc/build-files/Dockerfile`, `loc/config/settings-configmap.yaml`, `loc/edge/inline-block-comment.js`, `loc/generated-code/handwritten_client.ts`, `loc/generated-code/late_marker.ts`, `loc/minified/legacy-bundle.js`, `loc/minified/widget.js`, `loc/python/docstrings.py`, `loc/terraform/main.tf`, `loc/xml/beans.xml`

Excluded loc/ files (21): `loc/build-files/Makefile`, `loc/build-files/README.md`, `loc/build-files/build.gradle.kts`, `loc/config/application.yml`, `loc/config/docker-compose.yml`, `loc/excluded-files/Cargo.lock`, `loc/excluded-files/Gemfile.lock`, `loc/excluded-files/composer.lock`, `loc/excluded-files/go.sum`, `loc/excluded-files/npm-shrinkwrap.json`, `loc/excluded-files/package-lock.json`, `loc/excluded-files/package.json`, `loc/excluded-files/pnpm-lock.yaml`, `loc/excluded-files/poetry.lock`, `loc/excluded-files/uv.lock`, `loc/excluded-files/yarn.lock`, `loc/generated-code/Settings.cs`, `loc/generated-code/api_client.ts`, `loc/generated-code/events_pb2.py`, `loc/generated-code/queries.go`, `loc/minified/analytics.min.js`

### worker counter (local build)

Total code lines: expected **4000**, actual **3999** (**differs**)

| Language | Expected | Actual |
|---|---:|---:|
| c | 79 | 79 |
| cpp | 11 | 11 |
| dockerfile | 6 | 6 |
| go | 334 | 334 |
| java | 135 | 135 |
| javascript | 915 | 914 ⚠ |
| php | 182 | 182 |
| python | 1977 | 1977 |
| shell | 177 | 177 |
| terraform | 13 | 13 |
| typescript | 151 | 151 |
| xml | 7 | 7 |
| yaml | 13 | 13 |

Unexpectedly counted: none

Missing counted files: none

| File | Expected | Actual | Note |
|---|---:|---:|---|
| `loc/edge/inline-block-comment.js` | 3 | 2 | known TigerGate model divergence |

### CLI counter

Total code lines: expected **4000**, actual **3999** (**differs**)

| Language | Expected | Actual |
|---|---:|---:|
| c | 79 | 79 |
| cpp | 11 | 11 |
| dockerfile | 6 | 6 |
| go | 334 | 334 |
| java | 135 | 135 |
| javascript | 915 | 914 ⚠ |
| php | 182 | 182 |
| python | 1977 | 1977 |
| shell | 177 | 177 |
| terraform | 13 | 13 |
| typescript | 151 | 151 |
| xml | 7 | 7 |
| yaml | 13 | 13 |

Unexpectedly counted: none

Missing counted files: none

| File | Expected | Actual | Note |
|---|---:|---:|---|
| `loc/edge/inline-block-comment.js` | 3 | 2 | known TigerGate model divergence |

Worker vs CLI counter: **identical**

SonarCloud: **pending** (no analysis of this exact commit supplied).
