# Token usage and cost report

Final full-dataset run that produced `output.csv` (518 requests, `python3 code/main.py`).

| Provider | Model | Model calls | Input tokens | Output tokens | Est. cost (USD) |
|---|---|---|---|---|---|
| none | none (deterministic Python pipeline) | 0 | 0 | 0 | 0.00 |

| Overall | Value |
|---|---|
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |

No LLM is called at inference time: parsing, identity resolution, policy evaluation, decisions and
serialization are deterministic. Screenshot/PDF text comes from local `tesseract` and `pdftotext`
(no API, no cost). The run needs no API key or network access. Wall time for the full run is roughly 30 s.
