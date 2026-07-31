import { alpha, styled } from "@mui/material/styles";
import { Allotment } from "allotment";
import React from "react";

// This wrapper exists so the five call sites do not have to care which library
// draws the divider. It keeps react-split-pane's prop names and semantics:
//
//   split="vertical"    panes sit side by side, divider runs top to bottom
//   split="horizontal"  panes stack, divider runs left to right
//   size                the size of the FIRST pane
//
// Allotment inverts the first of those: it lays panes out side by side by
// default and takes a `vertical` flag to stack them. Translating here rather
// than at each call site keeps the change to one file, and keeps the prop
// meaning what it has always meant in this codebase.

const SIZE_FACTOR = 4;

export interface SplitPaneProps {
  split?: "vertical" | "horizontal";
  /** Size of the first pane. A percentage string or a number of pixels. */
  size?: string | number;
  className?: string;
  children: [React.ReactNode, React.ReactNode];
}

const StyledAllotment = styled(Allotment)(({ theme }) => ({
  // Allotment is themed through CSS custom properties rather than class
  // overrides, so the palette is handed to it here.
  "--focus-border": theme.palette.primary.main,
  "--separator-border": alpha(theme.palette.grey[400], 0.05),
  "--sash-size": theme.spacing(SIZE_FACTOR),
  "--sash-hover-size": theme.spacing(SIZE_FACTOR),
  height: "100%",
  width: "100%",
}));

// Allotment gives each pane a definite size but does not stretch what is
// inside it. react-split-pane did, so several call sites hand it a child with
// height: 100% and nothing else. Against an auto-height parent that resolves to
// zero, which collapses any nested SplitPane and blanks the panel. Stretching
// the child here keeps that contract in one place instead of adding a height to
// every call site.
const PaneContent = styled("div")({
  display: "flex",
  flexDirection: "column",
  height: "100%",
  width: "100%",
  "& > *": {
    flex: "1 1 auto",
    minHeight: 0,
  },
});

function SplitPane({ split = "vertical", size, className, children }: SplitPaneProps): JSX.Element {
  const [first, second] = children;

  return (
    <StyledAllotment className={className} vertical={split === "horizontal"}>
      <Allotment.Pane preferredSize={size}>
        <PaneContent>{first}</PaneContent>
      </Allotment.Pane>
      <Allotment.Pane>
        <PaneContent>{second}</PaneContent>
      </Allotment.Pane>
    </StyledAllotment>
  );
}

export default SplitPane;
