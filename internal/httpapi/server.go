package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"

	"github.com/NEU-DitingLab/go-ditecting/internal/auth"
	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
	"github.com/NEU-DitingLab/go-ditecting/internal/platform"
)

//go:embed web/*
var webFiles embed.FS

type API struct {
	service       *platform.Service
	auth          *auth.Manager
	ingestKey     string
	allowedOrigin string
}

func New(addr string, service *platform.Service, manager *auth.Manager, ingestKey, allowedOrigin string) *server.Hertz {
	api := &API{service: service, auth: manager, ingestKey: ingestKey, allowedOrigin: allowedOrigin}
	h := server.Default(server.WithHostPorts(addr))
	h.Use(api.cors())
	h.GET("/", api.file("web/index.html", "text/html; charset=utf-8"))
	h.GET("/styles.css", api.file("web/styles.css", "text/css; charset=utf-8"))
	h.GET("/app.js", api.file("web/app.js", "application/javascript; charset=utf-8"))
	h.GET("/healthz", api.health)
	h.GET("/metrics", api.metrics)
	h.POST("/api/v1/auth/login", api.login)
	h.POST("/api/v1/events", api.ingestAuth(), api.ingest)

	secured := h.Group("/api/v1", api.requireAuth())
	secured.GET("/overview", api.overview)
	secured.GET("/assets", api.assets)
	secured.GET("/alerts", api.alerts)
	secured.PATCH("/alerts/:id", api.updateAlert)
	secured.GET("/events", api.events)
	secured.GET("/rules", api.rules)
	secured.GET("/incidents", api.incidents)
	secured.POST("/incidents", api.createIncident)
	secured.POST("/demo/generate", api.generateDemo)
	return h
}

func (a *API) file(name, contentType string) app.HandlerFunc {
	data, err := webFiles.ReadFile(name)
	return func(_ context.Context, c *app.RequestContext) {
		if err != nil {
			c.String(http.StatusNotFound, "asset not found")
			return
		}
		c.Data(http.StatusOK, contentType, data)
	}
}

func (a *API) cors() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		origin := string(c.Request.Header.Peek("Origin"))
		if origin != "" && (a.allowedOrigin == "*" || origin == a.allowedOrigin) {
			c.Response.Header.Set("Access-Control-Allow-Origin", origin)
			c.Response.Header.Set("Vary", "Origin")
		}
		c.Response.Header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Ingest-Key")
		c.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		c.Response.Header.Set("X-Content-Type-Options", "nosniff")
		c.Response.Header.Set("X-Frame-Options", "DENY")
		if string(c.Method()) == http.MethodOptions {
			c.Status(http.StatusNoContent)
			c.Abort()
			return
		}
		c.Next(ctx)
	}
}

func (a *API) requireAuth() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		header := string(c.Request.Header.Peek("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") {
			fail(c, http.StatusUnauthorized, "请先登录")
			c.Abort()
			return
		}
		if _, err := a.auth.Verify(strings.TrimPrefix(header, "Bearer ")); err != nil {
			fail(c, http.StatusUnauthorized, "登录状态已失效")
			c.Abort()
			return
		}
		c.Next(ctx)
	}
}

func (a *API) ingestAuth() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if key := string(c.Request.Header.Peek("X-Ingest-Key")); key == a.ingestKey && key != "" {
			c.Next(ctx)
			return
		}
		header := string(c.Request.Header.Peek("Authorization"))
		if strings.HasPrefix(header, "Bearer ") {
			if _, err := a.auth.Verify(strings.TrimPrefix(header, "Bearer ")); err == nil {
				c.Next(ctx)
				return
			}
		}
		fail(c, http.StatusUnauthorized, "缺少有效的接入凭据")
		c.Abort()
	}
}

func (a *API) health(_ context.Context, c *app.RequestContext) {
	c.JSON(http.StatusOK, utils.H{"status": "ok", "service": "go-ditecting-api", "time": time.Now()})
}

func (a *API) metrics(_ context.Context, c *app.RequestContext) {
	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(a.service.Metrics.Prometheus()))
}

func (a *API) login(_ context.Context, c *app.RequestContext) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(c.Request.Body(), &input); err != nil {
		fail(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	token, err := a.auth.Authenticate(input.Username, input.Password)
	if err != nil {
		fail(c, http.StatusUnauthorized, err.Error())
		return
	}
	c.JSON(http.StatusOK, utils.H{"token": token, "user": utils.H{"username": input.Username, "role": "analyst"}, "expires_in": 28800})
}

func (a *API) ingest(ctx context.Context, c *app.RequestContext) {
	var event domain.Event
	if err := json.Unmarshal(c.Request.Body(), &event); err != nil {
		fail(c, http.StatusBadRequest, "事件 JSON 格式错误")
		return
	}
	event, err := a.service.Ingest(ctx, event)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusAccepted, utils.H{"data": event})
}

func (a *API) overview(ctx context.Context, c *app.RequestContext) {
	item, err := a.service.Store.Overview(ctx)
	respond(c, item, err)
}
func (a *API) assets(ctx context.Context, c *app.RequestContext) {
	items, err := a.service.Store.ListAssets(ctx)
	respond(c, items, err)
}
func (a *API) alerts(ctx context.Context, c *app.RequestContext) {
	items, err := a.service.Store.ListAlerts(ctx, c.Query("status"), queryLimit(c))
	respond(c, items, err)
}
func (a *API) events(ctx context.Context, c *app.RequestContext) {
	items, err := a.service.Store.ListEvents(ctx, queryLimit(c))
	respond(c, items, err)
}
func (a *API) rules(_ context.Context, c *app.RequestContext) {
	c.JSON(http.StatusOK, utils.H{"data": a.service.Engine.Rules()})
}
func (a *API) incidents(ctx context.Context, c *app.RequestContext) {
	items, err := a.service.Store.ListIncidents(ctx)
	respond(c, items, err)
}

func (a *API) updateAlert(ctx context.Context, c *app.RequestContext) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "无效的告警 ID")
		return
	}
	var input struct {
		Status   string `json:"status"`
		Assignee string `json:"assignee"`
	}
	if json.Unmarshal(c.Request.Body(), &input) != nil {
		fail(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	allowed := map[string]bool{"open": true, "acknowledged": true, "investigating": true, "resolved": true}
	if input.Status != "" && !allowed[input.Status] {
		fail(c, http.StatusBadRequest, "无效的告警状态")
		return
	}
	if err := a.service.Store.UpdateAlert(ctx, id, input.Status, input.Assignee); err != nil {
		fail(c, http.StatusNotFound, err.Error())
		return
	}
	c.JSON(http.StatusOK, utils.H{"message": "updated"})
}

func (a *API) createIncident(ctx context.Context, c *app.RequestContext) {
	var item domain.Incident
	if err := json.Unmarshal(c.Request.Body(), &item); err != nil || item.Title == "" || len(item.AlertIDs) == 0 {
		fail(c, http.StatusBadRequest, "标题和告警 ID 不能为空")
		return
	}
	created, err := a.service.Store.CreateIncident(ctx, item)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusCreated, utils.H{"data": created})
}

func (a *API) generateDemo(ctx context.Context, c *app.RequestContext) {
	events := demoEvents(time.Now())
	accepted := 0
	for _, event := range events {
		if _, err := a.service.Ingest(ctx, event); err == nil {
			accepted++
		}
	}
	c.JSON(http.StatusAccepted, utils.H{"message": "模拟攻击事件已发送", "accepted": accepted})
}

func demoEvents(now time.Time) []domain.Event {
	abnormal, min, max := 126.8, 10.0, 100.0
	offHoursDay := now
	if now.Hour() < 8 {
		offHoursDay = now.Add(-24 * time.Hour)
	}
	offHours := time.Date(offHoursDay.Year(), offHoursDay.Month(), offHoursDay.Day(), 2, 30, 0, 0, now.Location())
	items := []domain.Event{
		{AssetIP: "10.20.1.11", AssetName: "PLC-1 灌装控制器", AssetType: "PLC", Zone: "生产一区", SourceIP: "172.16.8.66", Protocol: "modbus", EventType: "control", Action: "write_register", FunctionCode: 16, RegisterAddress: 40001, OccurredAt: offHours},
		{AssetIP: "10.20.1.11", AssetName: "PLC-1 灌装控制器", AssetType: "PLC", Zone: "生产一区", SourceIP: "10.20.1.21", Protocol: "modbus", EventType: "telemetry", Action: "read_holding_register", Value: &abnormal, ExpectedMin: &min, ExpectedMax: &max, Authorized: true, Success: true, OccurredAt: now.Add(time.Second)},
	}
	for i := 0; i < 5; i++ {
		items = append(items, domain.Event{AssetIP: "10.20.2.15", AssetName: "ENG-WS 工程师站", AssetType: "Workstation", Zone: "工程管理区", SourceIP: "172.16.8.88", Protocol: "s7comm", EventType: "authentication", Action: "login", Success: false, OccurredAt: now.Add(time.Duration(i+2) * time.Second)})
	}
	for i, port := range []int{21, 22, 80, 102, 443, 502, 44818, 20000} {
		items = append(items, domain.Event{AssetIP: "10.20.3.10", AssetName: "SCADA-SRV 监控服务器", AssetType: "SCADA", Zone: "控制中心", SourceIP: "172.16.9.19", Protocol: "tcp", EventType: "connection", Action: "connect", DestinationPort: port, OccurredAt: now.Add(time.Duration(i+8) * time.Second)})
	}
	return items
}

func queryLimit(c *app.RequestContext) int {
	value, err := strconv.Atoi(c.Query("limit"))
	if err != nil || value <= 0 {
		return 100
	}
	if value > 500 {
		return 500
	}
	return value
}
func respond(c *app.RequestContext, data any, err error) {
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, utils.H{"data": data})
}
func fail(c *app.RequestContext, status int, message string) {
	c.JSON(status, utils.H{"error": message})
}
