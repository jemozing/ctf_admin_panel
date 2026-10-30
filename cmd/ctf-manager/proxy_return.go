package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// Emergency port return still goes through the one live executor worker. A CLI
// never opens a second Manager or repeats container commands outside its journal.
func remoteProxyReturn(ctx context.Context, socket string, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("proxy return command required")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(errOut)
	cutover := f.String("cutover", "", "cutover ID from proxy-cutovers")
	proposal := f.String("proposal", "", "fresh reviewed return proposal ID")
	digest := f.String("digest", "", "exact reviewed return digest")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected proxy return arguments")
	}
	switch args[0] {
	case "proxy-cutovers":
		if *cutover != "" || *proposal != "" || *digest != "" {
			return errors.New("proxy-cutovers accepts no mutation options")
		}
	case "proxy-return-preview":
		if domain.ID(*cutover).Validate() != nil || *proposal != "" || *digest != "" {
			return errors.New("--cutover ID is required; review the returned plan before confirming")
		}
	case "proxy-return-confirm":
		if domain.ID(*proposal).Validate() != nil || domain.Digest(*digest).Validate() != nil || *cutover != "" {
			return errors.New("--proposal ID and --digest SHA256 from a fresh return preview are required")
		}
	default:
		return errors.New("unknown proxy return command")
	}
	api, err := transport.NewClient(socket)
	if err != nil {
		return err
	}
	defer api.Close()
	actor := domain.ID(fmt.Sprintf("uid-%d", os.Geteuid()))
	var value any
	switch args[0] {
	case "proxy-cutovers":
		value, err = api.ProxyCutovers(ctx)
	case "proxy-return-preview":
		value, err = api.ProxyCutoverReturnPreview(ctx, transport.ProxyCutoverReturnRequest{CutoverID: domain.ID(*cutover), Initiator: actor})
	case "proxy-return-confirm":
		value, err = api.ProxyCutoverConfirm(ctx, transport.ProxyConfirmRequest{ProposalID: domain.ID(*proposal), Digest: domain.Digest(*digest), Initiator: actor})
	}
	if err != nil {
		return err
	}
	return emit(out, value)
}
