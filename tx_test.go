package walletapi

import (
	"testing"
)

func TestChainClient_SignNoBalanceTransaction(t *testing.T) {
	txHex := "0a14757365722e702e74657374636861742e63686174122450661a200a1e0a086e69636b6e616d651208e6b58be8af956432180122067075626c696320a08d063088b3ad9ba0908eff083a22313671444d354758634a627869574e5a6664684d58747144354b5054487055446563"
	pk := "用户私钥"
	c, err := NewChainClient(&Config{
		Chain: Chain{
			FeePrikey: "代扣私钥",
			FeeAddr:   "",
			Title:     "user.p.testchat.",
			BaseExec:  "",
		},
		Encrypt: Encrypt{
			SignType: 1,
		},
	})
	if err != nil {
		t.Error(err)
		return
	}
	got, err := c.SignNoBalanceTransaction(txHex, pk)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("success: %v", got)
}

func TestChainClient_SignTransaction(t *testing.T) {
	txHex := "0a14757365722e702e74657374636861742e63686174122450661a200a1e0a086e69636b6e616d651208e6b58be8af956434180122067075626c696320a08d0630cfc38c9dd5afd69d6b3a22313671444d354758634a627869574e5a6664684d58747144354b5054487055446563"
	pk := ""
	c, err := NewChainClient(&Config{})
	if err != nil {
		t.Error(err)
		return
	}
	got, err := c.SignTransaction(txHex, pk)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("success: %v", got)
}

func TestNewChainClient(t *testing.T) {
	type args struct {
		c *Config
	}
	tests := []struct {
		name    string
		args    args
		wantCli *ChainClient
		wantErr bool
	}{
		{
			name: "",
			args: args{
				c: &Config{
					Chain: Chain{
						FeePrikey: "",
						FeeAddr:   "",
						Title:     "",
						BaseExec:  "",
					},
					Encrypt: Encrypt{},
				},
			},
			wantCli: nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewChainClient(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewChainClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestChainClient_SignTransactionGroup(t *testing.T) {
	txHex := "0x0a14757365722e702e74657374636861742e6e6f6e6512126e6f2d6665652d7472616e73616374696f6e1a6e080112210299ed1505c19c58e6f89f90c8382ba39255cf4e73eb9e4ed9840b92f2e5881aa91a47304502210096dcc1a22c65bfbef2176a62128b72939728dcb82313e26f5ba6b7c97cafa9f2022018ebc1d93b9e41408d29273cd00f7f1e4296ed086246d70454d574bd4895f90b20c09a0c2893d3bf8b0630af9689acfc9fb7e37b3a22314443766875635a5a3762794b6a6972534569554e5661644151544e37613175684140024aac030a98020a14757365722e702e74657374636861742e6e6f6e6512126e6f2d6665652d7472616e73616374696f6e1a6e080112210299ed1505c19c58e6f89f90c8382ba39255cf4e73eb9e4ed9840b92f2e5881aa91a47304502210096dcc1a22c65bfbef2176a62128b72939728dcb82313e26f5ba6b7c97cafa9f2022018ebc1d93b9e41408d29273cd00f7f1e4296ed086246d70454d574bd4895f90b20c09a0c2893d3bf8b0630af9689acfc9fb7e37b3a22314443766875635a5a3762794b6a6972534569554e5661644151544e37613175684140024a20546e2b8d9bf55e89617aa14b44047f2a1741baa9ac4cfa74f5f2e0fee3d5ac925220a7fad3f1830276098c9b68086ed1e9788194887a531eb52ea7b3d25417aa88350a8e010a14757365722e702e74657374636861742e63686174122450661a200a1e0a086e69636b6e616d651208e6b58be8af956435180122067075626c696330acbfe0efadc1e4fd393a22313671444d354758634a627869574e5a6664684d58747144354b505448705544656340024a20546e2b8d9bf55e89617aa14b44047f2a1741baa9ac4cfa74f5f2e0fee3d5ac925220a7fad3f1830276098c9b68086ed1e9788194887a531eb52ea7b3d25417aa8835"
	pk := ""
	c, err := NewChainClient(&Config{})
	if err != nil {
		t.Error(err)
		return
	}
	got, err := c.SignTransactionGroup(2, txHex, pk)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("success: %v", got)
}
