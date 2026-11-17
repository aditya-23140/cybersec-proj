from setuptools import setup, find_packages

setup(
    name="fihhguard-ml-v2",
    version="2.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "fihhguard-train=ml.v2.training.cli:fihhguard_train",
            "fihhguard-evaluate=ml.v2.training.cli:fihhguard_evaluate",
            "fihhguard-predict=ml.v2.training.cli:fihhguard_predict",
        ],
    },
)
