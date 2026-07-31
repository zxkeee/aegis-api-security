// The one decorative graphic on the page: a single-line trace standing in for
// a request waveform, echoing the reference's ridge-line device without
// literally reusing mountains (this product's "terrain" is traffic, not land).
export default function SignalLine() {
  return (
    <svg
      viewBox="0 0 1200 90"
      preserveAspectRatio="none"
      className="h-[70px] w-full text-faint"
      aria-hidden="true"
    >
      <path
        d="M0 60 L90 60 L120 30 L150 72 L180 18 L210 60 L260 60 L290 44 L320 60 L400 60 L430 12 L460 78 L490 60 L560 60 L590 36 L610 60 L680 60 L710 24 L740 66 L770 60 L860 60 L890 42 L920 60 L1000 60 L1030 20 L1060 74 L1090 60 L1200 60"
        fill="none"
        stroke="currentColor"
        strokeWidth="1"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}
