package echo

import "testing"

func TestTargetConfigGetAuthorityOmitsDefaultPorts(t *testing.T) {
	tests := []struct {
		name     string
		target   TargetConfig
		protocol string
		want     string
	}{
		{
			name:     "https default port",
			target:   TargetConfig{Host: "wms-cn.urbanic-wms.cn", Port: 443},
			protocol: "https",
			want:     "wms-cn.urbanic-wms.cn",
		},
		{
			name:     "http default port",
			target:   TargetConfig{Host: "example.com", Port: 80},
			protocol: "http",
			want:     "example.com",
		},
		{
			name:     "local non-default port",
			target:   TargetConfig{Host: "127.0.0.1", Port: 3333},
			protocol: "http",
			want:     "127.0.0.1:3333",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.target.GetAuthority(tt.protocol); got != tt.want {
				t.Fatalf("GetAuthority() = %q, want %q", got, tt.want)
			}
		})
	}
}
