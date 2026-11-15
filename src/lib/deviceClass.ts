/**
 * Genuine mobile device detection, resolved once when the module loads.
 *
 * The check never looks at the viewport: a desktop browser narrowed with DevTools,
 * resized, or opened in a small window stays a desktop, while a real phone stays a
 * phone in landscape. That keeps device-specific simplifications honest.
 */
function resolveMobileDevice(): boolean {
  if (typeof navigator === 'undefined') return false;

  const nav = navigator as Navigator & { userAgentData?: { mobile?: boolean } };
  if (nav.userAgentData?.mobile === true) return true;

  const ua = nav.userAgent || '';
  if (
    /Android|iPhone|iPod|IEMobile|Opera Mini|Mobile|Silk|Kindle|PlayBook|BlackBerry|webOS/i.test(
      ua
    )
  ) {
    return true;
  }

  // iPadOS 13+ reports a desktop-class Mac user agent. Only real touch hardware matches.
  return /Macintosh/.test(ua) && (nav.maxTouchPoints ?? 0) > 1;
}

export const isMobileDevice = resolveMobileDevice();
