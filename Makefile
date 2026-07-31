export CGO_ENABLED = 0
export NEXT_TELEMETRY_DISABLED = 1

.PHONY: build
build: build-admin
	go build ./cmd/hetty

.PHONY: build-admin
build-admin:
	cd admin && \
	yarn install --frozen-lockfile && \
	yarn run export
# Without this, a second `make build` moves the fresh export *into* the
# existing directory as cmd/hetty/admin/dist, because that is what mv does when
# the destination is an existing directory. The go:embed directive then bakes
# in the previous build and the binary silently ships a stale UI.
	rm -rf ./cmd/hetty/admin
	mv admin/dist ./cmd/hetty/admin

.PHONY: clean
clean:
	rm -f hetty
	rm -rf ./cmd/hetty/admin
	rm -rf ./admin/dist
	rm -rf ./admin/.next