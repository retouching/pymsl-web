from pydantic import BaseModel, ConfigDict


class Run(BaseModel):
    model_config = ConfigDict(frozen=True)

    exit_code: int
    stdout: str
    stderr: str
