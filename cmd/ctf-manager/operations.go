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

func remoteOperation(ctx context.Context, socket string, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	service := flags.String("service", "", "registered service ID")
	operation := flags.String("operation", "", "durable operation ID")
	requestFile := flags.String("request", "", "typed operation request JSON; no command or path fields")
	plan := flags.String("plan", "", "reviewed executor preview digest")
	confirm := flags.Bool("confirm-data", false, "confirm reviewed release/persistent-data compatibility")
	after := flags.Uint64("after", 0, "diagnostic chunk cursor")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	client, err := transport.NewClient(socket)
	if err != nil {
		return err
	}
	defer client.Close()
	switch args[0] {
	case "cancel":
		value, err := client.CancelOperation(ctx, domain.ID(*operation), domain.ID(fmt.Sprintf("uid-%d", os.Geteuid())))
		if err != nil {
			return err
		}
		return emit(out, value)
	case "diagnostics":
		value, err := client.OperationDiagnostics(ctx, domain.ID(*operation), *after)
		if err != nil {
			return err
		}
		return emit(out, value)
	case "service":
		value, err := client.ServiceDetails(ctx, domain.ID(*service))
		if err != nil {
			return err
		}
		return emit(out, value)
	case "operation":
		value, err := client.GetOperation(ctx, domain.ID(*operation))
		if err != nil {
			return err
		}
		return emit(out, value)
	case "events":
		value, err := client.OperationEvents(ctx, domain.ID(*operation))
		if err != nil {
			return err
		}
		return emit(out, value)
	case "preview", "submit":
		if *requestFile == "" {
			return errors.New("--request FILE is required")
		}
		var req transport.SubmitRequest
		if err := loadJSON(*requestFile, &req); err != nil {
			return err
		}
		if *plan != "" {
			req.PlanDigest = domain.Digest(*plan)
		}
		if *confirm {
			req.ConfirmDataCompatibility = true
		}
		if args[0] == "preview" {
			value, err := client.Preview(ctx, req)
			if err != nil {
				return err
			}
			return emit(out, value)
		}
		value, err := client.Submit(ctx, req)
		if err != nil {
			return err
		}
		return emit(out, value)
	}
	return errors.New("unsupported remote operation command")
}
