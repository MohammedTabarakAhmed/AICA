# Training an AICA adapter on Kaggle (BRD 13)

Training happens on a free Kaggle GPU under your own account. Everything that leaves this
machine is staged first, and you read it before uploading. The credentials stay in your
environment. They are never written into this repository or read by `aica`.

## Once: account and API token

1. Create an account at <https://www.kaggle.com> and **verify your phone number**
   (Settings → Phone verification). Kaggle only gives GPUs and internet access in notebooks to
   verified accounts.
2. Settings → **API** → **Create New Token**. It downloads `kaggle.json`, which contains your
   username and a key.
3. Put both in **user environment variables**, not in a file in this repository (Windows):

   ```
   setx KAGGLE_USERNAME "your-username"
   setx KAGGLE_KEY "the-key-from-kaggle.json"
   ```

   Open a new terminal so they take effect, then delete the downloaded `kaggle.json`.
4. Install the Kaggle CLI in the project's virtual environment:
   `.venv\Scripts\python -m pip install "kaggle>=1.7,<2"`, then check it with
   `.venv\Scripts\kaggle datasets list --mine`.

## Each training run

```
aica adapt collect                          # screen practice/agent runs into candidates
aica adapt candidates                       # review; then approve each one you accept:
aica adapt approve <id>                     # (with RBAC on, not the run's author: SEC-006)
aica adapt dataset                          # build the immutable dataset
aica adapt plan --name aica-coder --base qwen2.5-coder-7b --dataset <version>
aica adapt export --job <config_version> --kaggle-user <you> --out .aica/export
```

**Read `.aica/export/review.md`.** It shows every training example in plain text, exactly as
it will be uploaded. Uploading is the step that sends data off this machine, so only continue
if you're happy with what's there:

```
kaggle datasets create -p .aica/export          # a private dataset
kaggle kernels push -p .aica/export/kernel      # a private notebook run on a GPU
kaggle kernels status <you>/aica-qlora-<config_version>
kaggle kernels output <you>/aica-qlora-<config_version> -p .aica/adapters/<name>
```

The notebook (`qlora_adapter.ipynb`) refuses to train unless the dataset's SHA-256 matches its
manifest and the job. It trains only on the answers, and it writes `provenance.json` with the
exact base-model revision and a digest of every output file.

## Back on this machine

```
# serve it locally: Ollama applies the GGUF adapter on the same base it was trained for
cd .aica/adapters/<name>/out
echo FROM qwen2.5-coder:7b> Modelfile
echo ADAPTER ./adapter.gguf>> Modelfile
ollama create aica-coder-1 -f Modelfile

aica adapt register --job <config_version> --serving-id aica-coder-1 --artifact .aica/adapters/<name>/out
aica eval run --adapter <id> --out candidate.json      # the golden tasks, with the adapter
aica eval run --model qwen2.5-coder-7b --out baseline.json
aica adapt evaluate <id> --report candidate.json --baseline baseline.json
aica adapt promote <id>                                # only if both gates passed
```

An adapter is served only after it passes the quality gate against the baseline and every
security-tagged golden task. `aica adapt rollback qwen2.5-coder-7b` undoes a promotion.
