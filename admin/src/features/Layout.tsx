import AccountTreeIcon from "@mui/icons-material/AccountTree";
import AltRouteIcon from "@mui/icons-material/AltRoute";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import BoltIcon from "@mui/icons-material/Bolt";
import BugReportIcon from "@mui/icons-material/BugReport";
import CallSplitIcon from "@mui/icons-material/CallSplit";
import CasinoIcon from "@mui/icons-material/Casino";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import CompareArrowsIcon from "@mui/icons-material/CompareArrows";
import DeviceHubIcon from "@mui/icons-material/DeviceHub";
import DnsIcon from "@mui/icons-material/Dns";
import ExtensionIcon from "@mui/icons-material/Extension";
import FindInPageIcon from "@mui/icons-material/FindInPage";
import FindReplaceIcon from "@mui/icons-material/FindReplace";
import FolderIcon from "@mui/icons-material/Folder";
import FormatListBulletedIcon from "@mui/icons-material/FormatListBulleted";
import HomeIcon from "@mui/icons-material/Home";
import HttpsIcon from "@mui/icons-material/Https";
import LabelIcon from "@mui/icons-material/Label";
import LocationSearchingIcon from "@mui/icons-material/LocationSearching";
import LoginIcon from "@mui/icons-material/Login";
import MenuIcon from "@mui/icons-material/Menu";
import PeopleIcon from "@mui/icons-material/People";
import SendIcon from "@mui/icons-material/Send";
import RuleIcon from "@mui/icons-material/Rule";
import SettingsInputAntennaIcon from "@mui/icons-material/SettingsInputAntenna";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import SyncAltIcon from "@mui/icons-material/SyncAlt";
import TerminalIcon from "@mui/icons-material/Terminal";
import TrackChangesIcon from "@mui/icons-material/TrackChanges";
import TransformIcon from "@mui/icons-material/Transform";
import TravelExploreIcon from "@mui/icons-material/TravelExplore";
import TuneIcon from "@mui/icons-material/Tune";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import {
  Theme,
  useTheme,
  Toolbar,
  IconButton,
  Typography,
  Divider,
  List,
  Tooltip,
  styled,
  CSSObject,
  Box,
  ListItemText,
  Badge,
} from "@mui/material";
import MuiAppBar, { AppBarProps as MuiAppBarProps } from "@mui/material/AppBar";
import MuiDrawer from "@mui/material/Drawer";
import MuiListItemButton, { ListItemButtonProps } from "@mui/material/ListItemButton";
import MuiListItemIcon, { ListItemIconProps } from "@mui/material/ListItemIcon";
import Link from "next/link";
import React, { useState } from "react";

import { useActiveProject } from "lib/ActiveProjectContext";
import { useInterceptedRequests } from "lib/InterceptedRequestsContext";

export enum Page {
  Home,
  GetStarted,
  Intercept,
  Projects,
  ProxySetup,
  ProxyLogs,
  Sender,
  Scope,
  Settings,
  Scanner,
  Spider,
  Intruder,
  Decoder,
  Comparer,
  Sequencer,
  Rules,
  Extensions,
  Collab,
  Authz,
  Sessions,
  Discovery,
  Sitemap,
  Jwt,
  Annotations,
  ParamMiner,
  GraphQL,
  Smuggle,
  WebSocket,
  AIAnalyst,
  Recon,
  Templates,
  Macros,
  PoC,
  WSRepeater,
  AttackSurface,
  ExternalTools,
}

const drawerWidth = 240;

const openedMixin = (theme: Theme): CSSObject => ({
  width: drawerWidth,
  transition: theme.transitions.create("width", {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.enteringScreen,
  }),
  overflowX: "hidden",
});

const closedMixin = (theme: Theme): CSSObject => ({
  transition: theme.transitions.create("width", {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.leavingScreen,
  }),
  overflowX: "hidden",
  width: 56,
});

const DrawerHeader = styled("div")(({ theme }) => ({
  display: "flex",
  alignItems: "center",
  justifyContent: "flex-start",
  padding: theme.spacing(0, 1),
  // necessary for content to be below app bar
  ...theme.mixins.toolbar,
}));

interface AppBarProps extends MuiAppBarProps {
  open?: boolean;
}

const AppBar = styled(MuiAppBar, {
  shouldForwardProp: (prop) => prop !== "open",
})<AppBarProps>(({ theme, open }) => ({
  backgroundColor: theme.palette.secondary.dark,
  zIndex: theme.zIndex.drawer + 1,
  transition: theme.transitions.create(["width", "margin"], {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.leavingScreen,
  }),
  ...(open && {
    marginLeft: drawerWidth,
    width: `calc(100% - ${drawerWidth}px)`,
    transition: theme.transitions.create(["width", "margin"], {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  }),
}));

const Drawer = styled(MuiDrawer, { shouldForwardProp: (prop) => prop !== "open" })(({ theme, open }) => ({
  width: drawerWidth,
  flexShrink: 0,
  whiteSpace: "nowrap",
  boxSizing: "border-box",
  ...(open && {
    ...openedMixin(theme),
    "& .MuiDrawer-paper": openedMixin(theme),
  }),
  ...(!open && {
    ...closedMixin(theme),
    "& .MuiDrawer-paper": closedMixin(theme),
  }),
}));

const ListItemButton = styled(MuiListItemButton)<ListItemButtonProps>(({ theme }) => ({
  [theme.breakpoints.up("sm")]: {
    px: 1,
  },
  "&.MuiListItemButton-root": {
    "&.Mui-selected": {
      backgroundColor: theme.palette.primary.main,
      "& .MuiListItemIcon-root": {
        color: theme.palette.secondary.dark,
      },
      "& .MuiListItemText-root": {
        color: theme.palette.secondary.dark,
      },
    },
  },
}));

const ListItemIcon = styled(MuiListItemIcon)<ListItemIconProps>(() => ({
  minWidth: 42,
}));

interface Props {
  children: React.ReactNode;
  title: string;
  page: Page;
}

export function Layout({ title, page, children }: Props): JSX.Element {
  const activeProject = useActiveProject();
  const interceptedRequests = useInterceptedRequests();
  const theme = useTheme();
  const [open, setOpen] = useState(false);

  const handleDrawerOpen = () => {
    setOpen(true);
  };

  const handleDrawerClose = () => {
    setOpen(false);
  };

  const SiteTitle = styled("span")({
    ...(title !== "" && {
      color: theme.palette.primary.main,
      marginRight: 4,
    }),
  });

  return (
    <Box sx={{ display: "flex", height: "100%" }}>
      <AppBar position="fixed" open={open}>
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="Open drawer"
            onClick={handleDrawerOpen}
            edge="start"
            sx={{
              mr: 5,
              ...(open && { display: "none" }),
            }}
          >
            <MenuIcon />
          </IconButton>
          <Box
            sx={{
              display: "flex",
              justifyContent: "space-around",
              width: "100%",
            }}
          >
            <Typography variant="h5" noWrap sx={{ width: "100%" }}>
              <SiteTitle>Hetty://</SiteTitle>
              {title}
            </Typography>
            <Box sx={{ flexShrink: 0, pt: 0.75 }}>v{process.env.NEXT_PUBLIC_VERSION || "0.0"}</Box>
          </Box>
        </Toolbar>
      </AppBar>
      <Drawer variant="permanent" open={open}>
        <DrawerHeader>
          <IconButton onClick={handleDrawerClose}>
            {theme.direction === "rtl" ? <ChevronRightIcon /> : <ChevronLeftIcon />}
          </IconButton>
        </DrawerHeader>
        <Divider />
        <List sx={{ p: 0 }}>
          <Link href="/" passHref>
            <ListItemButton key="home" selected={page === Page.Home}>
              <Tooltip title="Home">
                <ListItemIcon>
                  <HomeIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Home" />
            </ListItemButton>
          </Link>
          <Link href="/proxy/logs" passHref>
            <ListItemButton key="proxyLogs" disabled={!activeProject} selected={page === Page.ProxyLogs}>
              <Tooltip title="Proxy logs">
                <ListItemIcon>
                  <FormatListBulletedIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Logs" />
            </ListItemButton>
          </Link>
          <Link href="/proxy/intercept" passHref>
            <ListItemButton key="proxyIntercept" disabled={!activeProject} selected={page === Page.Intercept}>
              <Tooltip title="Proxy intercept">
                <ListItemIcon>
                  <Badge color="error" badgeContent={interceptedRequests?.length || 0}>
                    <AltRouteIcon />
                  </Badge>
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Intercept" />
            </ListItemButton>
          </Link>
          <Link href="/sender" passHref>
            <ListItemButton key="sender" disabled={!activeProject} selected={page === Page.Sender}>
              <Tooltip title="Sender">
                <ListItemIcon>
                  <SendIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Sender" />
            </ListItemButton>
          </Link>
          <Link href="/scope" passHref>
            <ListItemButton key="scope" disabled={!activeProject} selected={page === Page.Scope}>
              <Tooltip title="Scope">
                <ListItemIcon>
                  <LocationSearchingIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Scope" />
            </ListItemButton>
          </Link>
          <Divider />
          <Link href="/scanner" passHref>
            <ListItemButton key="scanner" disabled={!activeProject} selected={page === Page.Scanner}>
              <Tooltip title="Scanner">
                <ListItemIcon>
                  <BugReportIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Scanner" />
            </ListItemButton>
          </Link>
          <Link href="/spider" passHref>
            <ListItemButton key="spider" selected={page === Page.Spider}>
              <Tooltip title="Spider">
                <ListItemIcon>
                  <TravelExploreIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Spider" />
            </ListItemButton>
          </Link>
          <Link href="/intruder" passHref>
            <ListItemButton key="intruder" selected={page === Page.Intruder}>
              <Tooltip title="Intruder">
                <ListItemIcon>
                  <BoltIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Intruder" />
            </ListItemButton>
          </Link>
          <Link href="/decoder" passHref>
            <ListItemButton key="decoder" selected={page === Page.Decoder}>
              <Tooltip title="Decoder">
                <ListItemIcon>
                  <TransformIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Decoder" />
            </ListItemButton>
          </Link>
          <Link href="/comparer" passHref>
            <ListItemButton key="comparer" selected={page === Page.Comparer}>
              <Tooltip title="Comparer">
                <ListItemIcon>
                  <CompareArrowsIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Comparer" />
            </ListItemButton>
          </Link>
          <Link href="/sequencer" passHref>
            <ListItemButton key="sequencer" selected={page === Page.Sequencer}>
              <Tooltip title="Sequencer">
                <ListItemIcon>
                  <CasinoIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Sequencer" />
            </ListItemButton>
          </Link>
          <Link href="/rules" passHref>
            <ListItemButton key="rules" selected={page === Page.Rules}>
              <Tooltip title="Match & Replace">
                <ListItemIcon>
                  <FindReplaceIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Match & Replace" />
            </ListItemButton>
          </Link>
          <Link href="/extensions" passHref>
            <ListItemButton key="extensions" selected={page === Page.Extensions}>
              <Tooltip title="Extensions">
                <ListItemIcon>
                  <ExtensionIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Extensions" />
            </ListItemButton>
          </Link>
          <Link href="/collab" passHref>
            <ListItemButton key="collab" selected={page === Page.Collab}>
              <Tooltip title="Collaborator">
                <ListItemIcon>
                  <SettingsInputAntennaIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Collaborator" />
            </ListItemButton>
          </Link>
          <Link href="/authz" passHref>
            <ListItemButton key="authz" selected={page === Page.Authz}>
              <Tooltip title="Authorization tester">
                <ListItemIcon>
                  <HttpsIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Authz" />
            </ListItemButton>
          </Link>
          <Link href="/sessions" passHref>
            <ListItemButton key="sessions" selected={page === Page.Sessions}>
              <Tooltip title="Auth profiles">
                <ListItemIcon>
                  <PeopleIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Auth Profiles" />
            </ListItemButton>
          </Link>
          <Link href="/discovery" passHref>
            <ListItemButton key="discovery" selected={page === Page.Discovery}>
              <Tooltip title="Content discovery">
                <ListItemIcon>
                  <FindInPageIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Discovery" />
            </ListItemButton>
          </Link>
          <Link href="/sitemap" passHref>
            <ListItemButton key="sitemap" selected={page === Page.Sitemap}>
              <Tooltip title="Site map">
                <ListItemIcon>
                  <AccountTreeIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Site Map" />
            </ListItemButton>
          </Link>
          <Link href="/jwt" passHref>
            <ListItemButton key="jwt" selected={page === Page.Jwt}>
              <Tooltip title="JWT editor">
                <ListItemIcon>
                  <VpnKeyIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="JWT" />
            </ListItemButton>
          </Link>
          <Link href="/annotations" passHref>
            <ListItemButton key="annotations" selected={page === Page.Annotations}>
              <Tooltip title="Annotations">
                <ListItemIcon>
                  <LabelIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Annotations" />
            </ListItemButton>
          </Link>
          <Link href="/paramminer" passHref>
            <ListItemButton key="paramminer" selected={page === Page.ParamMiner}>
              <Tooltip title="Parameter discovery">
                <ListItemIcon>
                  <TuneIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Param Miner" />
            </ListItemButton>
          </Link>
          <Link href="/graphql" passHref>
            <ListItemButton key="graphql" selected={page === Page.GraphQL}>
              <Tooltip title="GraphQL">
                <ListItemIcon>
                  <DeviceHubIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="GraphQL" />
            </ListItemButton>
          </Link>
          <Link href="/smuggle" passHref>
            <ListItemButton key="smuggle" selected={page === Page.Smuggle}>
              <Tooltip title="Request smuggling probe">
                <ListItemIcon>
                  <CallSplitIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Smuggle" />
            </ListItemButton>
          </Link>
          <Link href="/websocket" passHref>
            <ListItemButton key="websocket" selected={page === Page.WebSocket}>
              <Tooltip title="WebSocket history">
                <ListItemIcon>
                  <SwapHorizIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="WebSockets" />
            </ListItemButton>
          </Link>
          <Link href="/asm" passHref>
            <ListItemButton key="asm" selected={page === Page.AttackSurface}>
              <Tooltip title="Attack surface (Sn1per-style sweeps)">
                <ListItemIcon>
                  <TrackChangesIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Attack Surface" />
            </ListItemButton>
          </Link>
          <Link href="/recon" passHref>
            <ListItemButton key="recon" selected={page === Page.Recon}>
              <Tooltip title="Recon">
                <ListItemIcon>
                  <DnsIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Recon" />
            </ListItemButton>
          </Link>
          <Link href="/tools" passHref>
            <ListItemButton key="exttools" selected={page === Page.ExternalTools}>
              <Tooltip title="External tools (nmap, nikto, nuclei, ...)">
                <ListItemIcon>
                  <TerminalIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="External Tools" />
            </ListItemButton>
          </Link>
          <Link href="/templates" passHref>
            <ListItemButton key="templates" selected={page === Page.Templates}>
              <Tooltip title="Templated scanner">
                <ListItemIcon>
                  <RuleIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Templates" />
            </ListItemButton>
          </Link>
          <Link href="/macros" passHref>
            <ListItemButton key="macros" selected={page === Page.Macros}>
              <Tooltip title="Session macros">
                <ListItemIcon>
                  <LoginIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Macros" />
            </ListItemButton>
          </Link>
          <Link href="/wsrepeater" passHref>
            <ListItemButton key="wsrepeater" selected={page === Page.WSRepeater}>
              <Tooltip title="WebSocket repeater">
                <ListItemIcon>
                  <SyncAltIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="WS Repeater" />
            </ListItemButton>
          </Link>
          <Link href="/poc" passHref>
            <ListItemButton key="poc" selected={page === Page.PoC}>
              <Tooltip title="PoC generators (CSRF / clickjacking)">
                <ListItemIcon>
                  <BugReportIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="PoC Generators" />
            </ListItemButton>
          </Link>
          <Link href="/ai" passHref>
            <ListItemButton key="ai" selected={page === Page.AIAnalyst}>
              <Tooltip title="AI analyst">
                <ListItemIcon>
                  <AutoAwesomeIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="AI Analyst" />
            </ListItemButton>
          </Link>
          <Divider />
          <Link href="/projects" passHref>
            <ListItemButton key="projects" selected={page === Page.Projects}>
              <Tooltip title="Projects">
                <ListItemIcon>
                  <FolderIcon />
                </ListItemIcon>
              </Tooltip>
              <ListItemText primary="Projects" />
            </ListItemButton>
          </Link>
        </List>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, mx: 3, mt: 11 }}>
        {children}
      </Box>
    </Box>
  );
}
