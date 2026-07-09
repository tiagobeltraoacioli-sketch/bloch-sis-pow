# Bloch-SIS PoW hardness estimator — SageMath + lattice-estimator.
#
# Builds a container that runs the lattice-estimator over the PoW parameter
# candidates (deploy/pow-estimator/estimate.py) and prints the hardness table.
#
#   docker build -t bloch-pow-estimator -f deploy/pow-estimator/Dockerfile .
#   docker run --rm bloch-pow-estimator
#
# Pin ESTIMATOR_REF to a commit for reproducibility once you settle on a version.

FROM sagemath/sagemath:10.3

USER root
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Clone the estimator's default branch (malb/lattice-estimator uses `main`, not
# `master`). Pin a commit + `git checkout` it for reproducibility once frozen.
RUN git clone --depth 1 https://github.com/malb/lattice-estimator /opt/lattice-estimator

WORKDIR /opt/lattice-estimator
COPY deploy/pow-estimator/estimate.py /opt/lattice-estimator/estimate.py

# `sage -python` gives the estimator its Sage-backed Python runtime.
ENTRYPOINT ["sage", "-python", "estimate.py"]
