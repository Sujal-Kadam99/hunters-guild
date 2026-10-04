import pytest
from hunters_guild.engine.orchestrator import GuildMaster

def test_guildmaster_temperature_routing():
    master = GuildMaster(
        agent_endpoint_url="http://mock",
        agent_api_key="mock",
        tactician_temperature=0.42,
        inquisitor_temperature=0.11,
        scribe_temperature=0.99
    )
    assert master.tactician.temperature == 0.42
    assert master.inquisitor.temperature == 0.11
    assert master.scribe.temperature == 0.99
