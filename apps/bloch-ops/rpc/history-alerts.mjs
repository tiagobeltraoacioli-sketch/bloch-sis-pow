export function compareChainObservations(previous, current) {
  if (previous?.status !== 'valid' || current?.status !== 'valid') {
    return { status: 'insufficient', alerts: [] };
  }
  const alerts = [];
  if (current.height < previous.height) {
    alerts.push({ code: 'head_regression', message: `Head height fell from ${previous.height} to ${current.height}.` });
  }
  if (current.finalized_height < previous.finalized_height) {
    alerts.push({ code: 'finality_regression', message: `Finalized height fell from ${previous.finalized_height} to ${current.finalized_height}.` });
  }
  const previousSlot = Number.isSafeInteger(previous.slot) && previous.slot >= 0 ? previous.slot : null;
  const currentSlot = Number.isSafeInteger(current.slot) && current.slot >= 0 ? current.slot : null;
  if (previousSlot !== null && currentSlot !== null) {
    if (currentSlot < previousSlot) {
      alerts.push({ code: 'slot_regression', message: `Head slot fell from ${previousSlot} to ${currentSlot}.` });
    }
    if (current.height === previous.height && currentSlot !== previousSlot) {
      alerts.push({ code: 'height_slot_conflict', message: `Height ${current.height} was reported at slots ${previousSlot} and ${currentSlot}.` });
    }
    if (currentSlot === previousSlot && current.height !== previous.height) {
      alerts.push({ code: 'slot_height_conflict', message: `Slot ${currentSlot} was reported at heights ${previous.height} and ${current.height}.` });
    }
  }
  return { status: alerts.length ? 'review' : 'consistent', alerts };
}
