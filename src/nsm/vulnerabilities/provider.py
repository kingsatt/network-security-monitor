from abc import ABC, abstractmethod

from nsm.vulnerabilities.models import Vulnerability


class VulnerabilityProvider(ABC):

    @abstractmethod
    def find_vulnerabilities(
        self,
        product: str,
        version: str,
    ) -> list[Vulnerability]:
        pass