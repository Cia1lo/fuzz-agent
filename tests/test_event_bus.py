import asyncio
from datetime import datetime, timedelta, timezone

from fuzz_agent.events.stream import EventBus, PlateauDetector
from fuzz_agent.state.models import EventKind, FuzzEvent


async def _next_event(gen):
    return await asyncio.wait_for(gen.__anext__(), timeout=1)


def test_single_subscriber_receives_events_in_order(make_event):
    async def scenario():
        bus = EventBus()
        sub = bus.subscribe("cid")
        first = asyncio.create_task(_next_event(sub))
        await asyncio.sleep(0)
        events = [
            make_event("cid", EventKind.HEARTBEAT, n=1),
            make_event("cid", EventKind.NEW_COVERAGE, n=2),
        ]

        bus.publish(events[0])
        assert await first == events[0]
        bus.publish(events[1])
        assert await _next_event(sub) == events[1]
        bus.close("cid")
        await sub.aclose()

    asyncio.run(scenario())


def test_multiple_subscribers_per_cid_both_receive_every_event(make_event):
    async def scenario():
        bus = EventBus()
        sub1 = bus.subscribe("cid")
        sub2 = bus.subscribe("cid")
        first1 = asyncio.create_task(_next_event(sub1))
        first2 = asyncio.create_task(_next_event(sub2))
        await asyncio.sleep(0)
        event = make_event("cid", EventKind.NEW_CRASH, crash="x")

        bus.publish(event)

        assert await first1 == event
        assert await first2 == event
        bus.close("cid")
        await sub1.aclose()
        await sub2.aclose()

    asyncio.run(scenario())


def test_close_terminates_subscribe_generator_cleanly():
    async def scenario():
        bus = EventBus()
        sub = bus.subscribe("cid")
        task = asyncio.create_task(_next_event(sub))
        await asyncio.sleep(0)

        bus.close("cid")

        try:
            await asyncio.wait_for(task, timeout=1)
        except StopAsyncIteration:
            pass
        else:
            raise AssertionError("subscription did not terminate with StopAsyncIteration")

    asyncio.run(scenario())


def test_plateau_detector_emits_after_idle_non_coverage_events():
    detector = PlateauDetector(idle_sec=5)
    start = datetime.now(timezone.utc)
    first = FuzzEvent(EventKind.HEARTBEAT, "cid", start, {})
    idle = FuzzEvent(EventKind.HEARTBEAT, "cid", start + timedelta(seconds=6), {})

    assert detector.feed(first) is None
    plateau = detector.feed(idle)

    assert plateau is not None
    assert plateau.kind is EventKind.PLATEAU
    assert plateau.payload == {"idle_sec": 5}


def test_plateau_detector_resets_on_new_coverage():
    detector = PlateauDetector(idle_sec=5)
    start = datetime.now(timezone.utc)

    assert detector.feed(FuzzEvent(EventKind.HEARTBEAT, "cid", start, {})) is None
    assert detector.feed(
        FuzzEvent(EventKind.NEW_COVERAGE, "cid", start + timedelta(seconds=4), {})
    ) is None
    assert detector.feed(
        FuzzEvent(EventKind.HEARTBEAT, "cid", start + timedelta(seconds=8), {})
    ) is None
    plateau = detector.feed(
        FuzzEvent(EventKind.HEARTBEAT, "cid", start + timedelta(seconds=10), {})
    )

    assert plateau is not None
    assert plateau.kind is EventKind.PLATEAU
