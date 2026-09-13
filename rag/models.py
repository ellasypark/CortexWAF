from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Event(BaseModel):
    """Deliberately accepts summaries, never raw request headers or bodies."""
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    application: str = Field(min_length=1, max_length=100, pattern=r'^[\w.-]+$')
    version: str = Field(default='current', min_length=1, max_length=100)
    endpoint: str = Field(min_length=1, max_length=300)
    method: Literal['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] = 'GET'
    attack_type: Literal['SQLI', 'XSS', 'RATE_LIMIT', 'IP_REPUTATION', 'UNKNOWN'] = 'UNKNOWN'
    rule_id: str = Field(default='', max_length=150)
    request_count: int | None = Field(default=None, ge=0)
    time_window_seconds: int | None = Field(default=None, gt=0)

    @field_validator('endpoint')
    @classmethod
    def endpoint_path(cls, value):
        if not value.startswith('/') or '?' in value or '#' in value:
            raise ValueError('Use a path or route template without query parameters or fragments')
        return value


class Verdict(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    decision: Literal['RECOMMEND', 'NO_CHANGE', 'NEEDS_REVIEW']
    rule_type: Literal['SQLI', 'XSS', 'RATE_LIMIT', 'IP_REPUTATION', 'NONE']
    rationale: str = Field(min_length=1, max_length=3000)
    citation_ids: list[str] = Field(default_factory=list, max_length=8)
    missing_context: list[str] = Field(default_factory=list, max_length=12)

    @model_validator(mode='after')
    def consistent(self):
        if self.decision == 'RECOMMEND' and self.rule_type == 'NONE':
            raise ValueError('A recommendation needs a rule type')
        if self.decision != 'RECOMMEND' and self.rule_type != 'NONE':
            raise ValueError('Only recommendations may specify a rule type')
        return self


class Feedback(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    decision: Literal['accepted', 'rejected']
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)
