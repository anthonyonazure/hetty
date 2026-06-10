import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import {
  Alert,
  Box,
  IconButton,
  Link,
  MenuItem,
  Snackbar,
  styled,
  TableCell,
  TableCellProps,
  Tooltip,
} from "@mui/material";
import { useApolloClient } from "@apollo/client";
import { useRouter } from "next/router";
import { useState } from "react";

import Actions from "./Actions";
import LogDetail from "./LogDetail";
import Search from "./Search";

import RequestsTable from "lib/components/RequestsTable";
import SplitPane from "lib/components/SplitPane";
import useContextMenu from "lib/components/useContextMenu";
import {
  HttpRequestLogDocument,
  HttpRequestLogQuery,
  useCreateSenderRequestFromHttpRequestLogMutation,
  useHttpRequestLogsQuery,
} from "lib/graphql/generated";
import { setHandoff } from "lib/handoff";

const ActionsTableCell = styled(TableCell)<TableCellProps>(() => ({
  paddingTop: 0,
  paddingBottom: 0,
}));

export function RequestLogs(): JSX.Element {
  const router = useRouter();
  const id = router.query.id as string | undefined;
  const { data } = useHttpRequestLogsQuery({
    pollInterval: 1000,
  });

  const [createSenderReqFromLog] = useCreateSenderRequestFromHttpRequestLogMutation({
    onCompleted({ createSenderRequestFromHttpRequestLog }) {
      const { id } = createSenderRequestFromHttpRequestLog;
      setNewSenderReqId(id);
      setCopiedReqNotifOpen(true);
    },
  });

  const [copyToSenderId, setCopyToSenderId] = useState("");
  const [Menu, handleContextMenu, handleContextMenuClose] = useContextMenu();
  const apollo = useApolloClient();

  const handleCopyToSenderClick = () => {
    createSenderReqFromLog({
      variables: {
        id: copyToSenderId,
      },
    });
    handleContextMenuClose();
  };

  const handleSendTo = async (tool: string, route: string) => {
    handleContextMenuClose();
    try {
      const { data: logData } = await apollo.query<HttpRequestLogQuery>({
        query: HttpRequestLogDocument,
        variables: { id: copyToSenderId },
        fetchPolicy: "network-only",
      });
      const log = logData?.httpRequestLog;
      if (!log) {
        return;
      }
      const headers = (log.headers || [])
        .filter((h) => h.key.toLowerCase() !== "host")
        .map((h) => `${h.key}: ${h.value}`)
        .join("\n");
      setHandoff(tool, {
        method: log.method,
        url: log.url,
        headers,
        body: log.body || "",
      });
      router.push(route);
    } catch {
      // ignore — handoff is best-effort
    }
  };

  const [newSenderReqId, setNewSenderReqId] = useState("");
  const [copiedReqNotifOpen, setCopiedReqNotifOpen] = useState(false);
  const handleCloseCopiedNotif = (_: Event | React.SyntheticEvent, reason?: string) => {
    if (reason === "clickaway") {
      return;
    }
    setCopiedReqNotifOpen(false);
  };

  const handleRowClick = (id: string) => {
    router.push(`/proxy/logs?id=${id}`);
  };

  const handleRowContextClick = (e: React.MouseEvent, id: string) => {
    setCopyToSenderId(id);
    handleContextMenu(e);
  };

  const actionsCell = (id: string) => (
    <ActionsTableCell>
      <Tooltip title="Copy to Sender">
        <IconButton
          size="small"
          onClick={() => {
            setCopyToSenderId(id);
            createSenderReqFromLog({
              variables: {
                id,
              },
            });
          }}
        >
          <ContentCopyIcon fontSize="small" />
        </IconButton>
      </Tooltip>
    </ActionsTableCell>
  );

  return (
    <Box display="flex" flexDirection="column" height="100%">
      <Box display="flex">
        <Box flex="1 auto">
          <Search />
        </Box>
        <Box pt={0.5}>
          <Actions />
        </Box>
      </Box>
      <Box sx={{ display: "flex", flex: "1 auto", position: "relative" }}>
        <SplitPane split="horizontal" size={"40%"}>
          <Box sx={{ width: "100%", height: "100%", pb: 2 }}>
            <Box sx={{ width: "100%", height: "100%", overflow: "scroll" }}>
              <Menu>
                <MenuItem onClick={handleCopyToSenderClick}>Copy request to Sender</MenuItem>
                <MenuItem onClick={() => handleSendTo("scanner", "/scanner")}>Send to Scanner</MenuItem>
                <MenuItem onClick={() => handleSendTo("intruder", "/intruder")}>Send to Intruder</MenuItem>
                <MenuItem onClick={() => handleSendTo("authz", "/authz")}>Send to Authz</MenuItem>
              </Menu>
              <Snackbar
                open={copiedReqNotifOpen}
                autoHideDuration={3000}
                onClose={handleCloseCopiedNotif}
                anchorOrigin={{ horizontal: "center", vertical: "bottom" }}
              >
                <Alert onClose={handleCloseCopiedNotif} severity="info">
                  Request was copied. <Link href={`/sender?id=${newSenderReqId}`}>Edit in Sender.</Link>
                </Alert>
              </Snackbar>
              <RequestsTable
                requests={data?.httpRequestLogs || []}
                activeRowId={id}
                actionsCell={actionsCell}
                onRowClick={handleRowClick}
                onContextMenu={handleRowContextClick}
              />
            </Box>
          </Box>
          <LogDetail id={id} />
        </SplitPane>
      </Box>
    </Box>
  );
}
