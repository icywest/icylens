from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class NVDDescription(BaseModel):
    model_config = ConfigDict(extra="ignore")

    lang: Annotated[str, Field(min_length=1, max_length=35)]
    value: Annotated[str, Field(min_length=1, max_length=32_768)]


class NVDCVSSData(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version: Annotated[str, Field(min_length=1, max_length=16)]
    vectorString: Annotated[str | None, Field(default=None, max_length=512)]
    baseScore: Annotated[float, Field(ge=0, le=10, allow_inf_nan=False)]
    baseSeverity: Annotated[str | None, Field(default=None, max_length=32)]


class NVDCVSSMetric(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source: Annotated[str, Field(min_length=1, max_length=320)]
    type: Annotated[str | None, Field(default=None, max_length=64)]
    cvssData: NVDCVSSData
    baseSeverity: Annotated[str | None, Field(default=None, max_length=32)]
    exploitabilityScore: Annotated[
        float | None, Field(default=None, ge=0, le=10, allow_inf_nan=False)
    ]
    impactScore: Annotated[
        float | None, Field(default=None, ge=0, le=10, allow_inf_nan=False)
    ]


class NVDMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cvssMetricV40: tuple[NVDCVSSMetric, ...] = ()
    cvssMetricV31: tuple[NVDCVSSMetric, ...] = ()
    cvssMetricV30: tuple[NVDCVSSMetric, ...] = ()
    cvssMetricV2: tuple[NVDCVSSMetric, ...] = ()


class NVDWeakness(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source: Annotated[str | None, Field(default=None, max_length=320)]
    type: Annotated[str | None, Field(default=None, max_length=64)]
    description: tuple[NVDDescription, ...] = ()


class NVDCPEMatch(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vulnerable: bool
    criteria: Annotated[str, Field(min_length=1, max_length=4096)]
    matchCriteriaId: Annotated[str | None, Field(default=None, max_length=64)]
    versionStartIncluding: Annotated[str | None, Field(default=None, max_length=256)]
    versionStartExcluding: Annotated[str | None, Field(default=None, max_length=256)]
    versionEndIncluding: Annotated[str | None, Field(default=None, max_length=256)]
    versionEndExcluding: Annotated[str | None, Field(default=None, max_length=256)]


class NVDConfigurationNode(BaseModel):
    model_config = ConfigDict(extra="ignore")

    operator: Annotated[str, Field(pattern=r"^(AND|OR)$")]
    negate: bool = False
    cpeMatch: tuple[NVDCPEMatch, ...] = ()
    nodes: tuple[NVDConfigurationNode, ...] = ()


class NVDConfiguration(BaseModel):
    model_config = ConfigDict(extra="ignore")

    operator: Annotated[str | None, Field(default=None, pattern=r"^(AND|OR)$")]
    negate: bool | None = None
    nodes: tuple[NVDConfigurationNode, ...] = ()
    cpeMatch: tuple[NVDCPEMatch, ...] = ()


class NVDReference(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: Annotated[str, Field(min_length=1, max_length=4096)]
    source: Annotated[str | None, Field(default=None, max_length=320)]
    tags: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = ()


class NVDCVE(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Annotated[str, Field(min_length=1, max_length=32)]
    sourceIdentifier: Annotated[str | None, Field(default=None, max_length=320)]
    published: Annotated[str | None, Field(default=None, max_length=64)]
    lastModified: Annotated[str | None, Field(default=None, max_length=64)]
    vulnStatus: Annotated[str | None, Field(default=None, max_length=128)]
    descriptions: tuple[NVDDescription, ...] = ()
    metrics: NVDMetrics = Field(default_factory=NVDMetrics)
    weaknesses: tuple[NVDWeakness, ...] = ()
    configurations: tuple[NVDConfiguration, ...] = ()
    references: tuple[NVDReference, ...] = ()


class NVDVulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cve: NVDCVE


class NVDResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    resultsPerPage: Annotated[int, Field(ge=0)]
    startIndex: Annotated[int, Field(ge=0)]
    totalResults: Annotated[int, Field(ge=0)]
    vulnerabilities: tuple[NVDVulnerability, ...]
    format: Literal["NVD_CVE"]
    version: Literal["2.0"]
    timestamp: Annotated[str | None, Field(default=None, max_length=64)]
