import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict

from tests.e2e.run import Run

ROOT: Final = Path(__file__).resolve().parents[2]
COMPOSE_FILE: Final = ROOT / "docker" / "compose.e2e.yaml"
BUILD_TIMEOUT_SECONDS: Final = 1800.0
UP_WAIT_SECONDS: Final = 180
RUN_TIMEOUT_SECONDS: Final = 300.0


class Stack(BaseModel):
    model_config = ConfigDict(frozen=True)

    services: ClassVar[tuple[str, ...]] = ("msl",)
    listings: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("ps", "--all"),
        ("volume", "ls"),
        ("network", "ls"),
        ("image", "ls"),
    )

    project: str

    @staticmethod
    def execute(arguments: list[str], timeout: float) -> Run:
        """Run `arguments` and keep its exit code and its decoded output."""
        finished = subprocess.run(arguments, capture_output=True, timeout=timeout, check=False)
        return Run(
            exit_code=finished.returncode,
            stdout=finished.stdout.decode(errors="replace"),
            stderr=finished.stderr.decode(errors="replace"),
        )

    def compose(self, *arguments: str, timeout: float = RUN_TIMEOUT_SECONDS) -> Run:
        """Run `docker compose <arguments>` on the project of the stack."""
        return self.execute(
            [
                "docker",
                "compose",
                "--progress",
                "quiet",
                "--project-name",
                self.project,
                "--file",
                str(COMPOSE_FILE),
                *arguments,
            ],
            timeout,
        )

    def start(self) -> None:
        """Build the image of the stack, then start its services and wait for their health."""
        built = self.compose("build", timeout=BUILD_TIMEOUT_SECONDS)
        if built.exit_code != 0:
            pytest.fail(f"The images of {self.project} were not built:\n{built.stderr}", pytrace=False)
        up = self.compose(
            "up",
            "--detach",
            "--wait",
            "--wait-timeout",
            str(UP_WAIT_SECONDS),
            *self.services,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
        if up.exit_code != 0:
            logs = self.compose("logs", "--no-color")
            pytest.fail(
                f"The services of {self.project} did not start:\n{up.stderr}\n--- logs ---\n{logs.stdout}{logs.stderr}",
                pytrace=False,
            )

    def url(self) -> str:
        """Give the base URL of the fake MSL server, on the port Docker published on the loopback."""
        port = self.compose("port", "msl", "8080")
        if port.exit_code != 0 or not port.stdout.strip():
            pytest.fail(f"The port of {self.project} is unknown:\n{port.stderr}", pytrace=False)
        return f"http://{port.stdout.strip()}"

    def remove(self) -> None:
        """Remove the containers, the volumes, the networks and the built images of the stack."""
        self.compose("down", "--volumes", "--remove-orphans", "--rmi", "local", timeout=BUILD_TIMEOUT_SECONDS)

    def leftovers(self) -> list[str]:
        """List each Docker object still labelled with the project of the stack."""
        label = f"label=com.docker.compose.project={self.project}"
        found: list[str] = []
        for listing in self.listings:
            listed = self.execute(["docker", *listing, "--filter", label, "--quiet"], RUN_TIMEOUT_SECONDS)
            found += [f"{listing[0]} {identifier}" for identifier in listed.stdout.split()]
        return found
