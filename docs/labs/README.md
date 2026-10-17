# IBM AI/ML labs

Both mandatory IBM AI/ML labs were run on our LinuxONE z17 L1CC VM on Oct 17, 2026. The notebooks are committed with their outputs.

## Fraud detection LSTM: [Fraud_LSTM_Keras_TF.ipynb](Fraud_LSTM_Keras_TF.ipynb)

Two-layer LSTM (200 units each, 633k parameters) in TensorFlow/Keras on credit-card transaction sequences (7 timesteps), exported to ONNX.

- **Test accuracy: 99.84%** (0.99837).
- **`ibm-zdnn-plugin` 2.3.0 loaded**: the plugin's kernel library (`_z_ops.so`, 17.5 MB) was found and loaded.
- **Inference throughput: 6,912 sequences/sec** (batch of 2,000 sequences, median of 10 runs: 289 ms).

## Loan approval (predictive + generative AI): [Loan_Approval_Demo.ipynb](Loan_Approval_Demo.ipynb)

Applicant 5 from the sample data:

- **XGBoost risk model**: Low Risk, probability 99.7% (0.9974).
- **Granite document extraction**: the IBM Granite model (via llama.cpp) read the bank statement, pay stub and W-2 and rated financial stability, cash flow and income consistency High, compliance Compliant.
- **BM25 RAG**: lending-policy documents indexed with BM25; the most relevant chunks were given to Granite.
- **Recommendation: Approve** ("High credit score, low DTI and stable documented income meet policy.")

## What we did and did not measure

- The zDNN plugin was **enabled** (installed and its library loaded). We did **not** measure whether operations actually ran on the NNPA accelerator: there is no NNPA usage counter or CPU-vs-NNPA comparison. The "Ops accelerated by NNPA" list in the fraud notebook is descriptive text, not a measurement, and 6,912 sequences/sec is total throughput, not an NNPA speedup.
- 99.84% accuracy is high partly because fraud is rare. At the last timestep the test set had 38 true positives, 24 false positives and 8 missed frauds.
- The loan notebook's llama.cpp build was compiled for z16 (`-march=z16`, `-DGGML_ZDNN=ON`). Its `libggml-zdnn.so` files are reported as 0.0 MB, so we make no NNPA claim for Granite. The model that ran was `granite-4.0-h-350m-base` (f16), not the `granite-3.3-2b-instruct` the notebook names as expected.
