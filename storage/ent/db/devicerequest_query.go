// Code generated by ent, DO NOT EDIT.

package db

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/dexidp/dex/storage/ent/db/devicerequest"
	"github.com/dexidp/dex/storage/ent/db/predicate"
)

// DeviceRequestQuery is the builder for querying DeviceRequest entities.
type DeviceRequestQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.DeviceRequest
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DeviceRequestQuery builder.
func (drq *DeviceRequestQuery) Where(ps ...predicate.DeviceRequest) *DeviceRequestQuery {
	drq.predicates = append(drq.predicates, ps...)
	return drq
}

// Limit adds a limit step to the query.
func (drq *DeviceRequestQuery) Limit(limit int) *DeviceRequestQuery {
	drq.limit = &limit
	return drq
}

// Offset adds an offset step to the query.
func (drq *DeviceRequestQuery) Offset(offset int) *DeviceRequestQuery {
	drq.offset = &offset
	return drq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (drq *DeviceRequestQuery) Unique(unique bool) *DeviceRequestQuery {
	drq.unique = &unique
	return drq
}

// Order adds an order step to the query.
func (drq *DeviceRequestQuery) Order(o ...OrderFunc) *DeviceRequestQuery {
	drq.order = append(drq.order, o...)
	return drq
}

// First returns the first DeviceRequest entity from the query.
// Returns a *NotFoundError when no DeviceRequest was found.
func (drq *DeviceRequestQuery) First(ctx context.Context) (*DeviceRequest, error) {
	nodes, err := drq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{devicerequest.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (drq *DeviceRequestQuery) FirstX(ctx context.Context) *DeviceRequest {
	node, err := drq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first DeviceRequest ID from the query.
// Returns a *NotFoundError when no DeviceRequest ID was found.
func (drq *DeviceRequestQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = drq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{devicerequest.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (drq *DeviceRequestQuery) FirstIDX(ctx context.Context) int {
	id, err := drq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single DeviceRequest entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one DeviceRequest entity is found.
// Returns a *NotFoundError when no DeviceRequest entities are found.
func (drq *DeviceRequestQuery) Only(ctx context.Context) (*DeviceRequest, error) {
	nodes, err := drq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{devicerequest.Label}
	default:
		return nil, &NotSingularError{devicerequest.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (drq *DeviceRequestQuery) OnlyX(ctx context.Context) *DeviceRequest {
	node, err := drq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only DeviceRequest ID in the query.
// Returns a *NotSingularError when more than one DeviceRequest ID is found.
// Returns a *NotFoundError when no entities are found.
func (drq *DeviceRequestQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = drq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{devicerequest.Label}
	default:
		err = &NotSingularError{devicerequest.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (drq *DeviceRequestQuery) OnlyIDX(ctx context.Context) int {
	id, err := drq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of DeviceRequests.
func (drq *DeviceRequestQuery) All(ctx context.Context) ([]*DeviceRequest, error) {
	if err := drq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return drq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (drq *DeviceRequestQuery) AllX(ctx context.Context) []*DeviceRequest {
	nodes, err := drq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of DeviceRequest IDs.
func (drq *DeviceRequestQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := drq.Select(devicerequest.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (drq *DeviceRequestQuery) IDsX(ctx context.Context) []int {
	ids, err := drq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (drq *DeviceRequestQuery) Count(ctx context.Context) (int, error) {
	if err := drq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return drq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (drq *DeviceRequestQuery) CountX(ctx context.Context) int {
	count, err := drq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (drq *DeviceRequestQuery) Exist(ctx context.Context) (bool, error) {
	if err := drq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return drq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (drq *DeviceRequestQuery) ExistX(ctx context.Context) bool {
	exist, err := drq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DeviceRequestQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (drq *DeviceRequestQuery) Clone() *DeviceRequestQuery {
	if drq == nil {
		return nil
	}
	return &DeviceRequestQuery{
		config:     drq.config,
		limit:      drq.limit,
		offset:     drq.offset,
		order:      append([]OrderFunc{}, drq.order...),
		predicates: append([]predicate.DeviceRequest{}, drq.predicates...),
		// clone intermediate query.
		sql:    drq.sql.Clone(),
		path:   drq.path,
		unique: drq.unique,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		UserCode string `json:"user_code,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.DeviceRequest.Query().
//		GroupBy(devicerequest.FieldUserCode).
//		Aggregate(db.Count()).
//		Scan(ctx, &v)
func (drq *DeviceRequestQuery) GroupBy(field string, fields ...string) *DeviceRequestGroupBy {
	grbuild := &DeviceRequestGroupBy{config: drq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := drq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return drq.sqlQuery(ctx), nil
	}
	grbuild.label = devicerequest.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		UserCode string `json:"user_code,omitempty"`
//	}
//
//	client.DeviceRequest.Query().
//		Select(devicerequest.FieldUserCode).
//		Scan(ctx, &v)
func (drq *DeviceRequestQuery) Select(fields ...string) *DeviceRequestSelect {
	drq.fields = append(drq.fields, fields...)
	selbuild := &DeviceRequestSelect{DeviceRequestQuery: drq}
	selbuild.label = devicerequest.Label
	selbuild.flds, selbuild.scan = &drq.fields, selbuild.Scan
	return selbuild
}

func (drq *DeviceRequestQuery) prepareQuery(ctx context.Context) error {
	for _, f := range drq.fields {
		if !devicerequest.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("db: invalid field %q for query", f)}
		}
	}
	if drq.path != nil {
		prev, err := drq.path(ctx)
		if err != nil {
			return err
		}
		drq.sql = prev
	}
	return nil
}

func (drq *DeviceRequestQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*DeviceRequest, error) {
	var (
		nodes = []*DeviceRequest{}
		_spec = drq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*DeviceRequest).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &DeviceRequest{config: drq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, drq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (drq *DeviceRequestQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := drq.querySpec()
	_spec.Node.Columns = drq.fields
	if len(drq.fields) > 0 {
		_spec.Unique = drq.unique != nil && *drq.unique
	}
	return sqlgraph.CountNodes(ctx, drq.driver, _spec)
}

func (drq *DeviceRequestQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := drq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("db: check existence: %w", err)
	}
	return n > 0, nil
}

func (drq *DeviceRequestQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   devicerequest.Table,
			Columns: devicerequest.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: devicerequest.FieldID,
			},
		},
		From:   drq.sql,
		Unique: true,
	}
	if unique := drq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := drq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, devicerequest.FieldID)
		for i := range fields {
			if fields[i] != devicerequest.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := drq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := drq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := drq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := drq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (drq *DeviceRequestQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(drq.driver.Dialect())
	t1 := builder.Table(devicerequest.Table)
	columns := drq.fields
	if len(columns) == 0 {
		columns = devicerequest.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if drq.sql != nil {
		selector = drq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if drq.unique != nil && *drq.unique {
		selector.Distinct()
	}
	for _, p := range drq.predicates {
		p(selector)
	}
	for _, p := range drq.order {
		p(selector)
	}
	if offset := drq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := drq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// DeviceRequestGroupBy is the group-by builder for DeviceRequest entities.
type DeviceRequestGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (drgb *DeviceRequestGroupBy) Aggregate(fns ...AggregateFunc) *DeviceRequestGroupBy {
	drgb.fns = append(drgb.fns, fns...)
	return drgb
}

// Scan applies the group-by query and scans the result into the given value.
func (drgb *DeviceRequestGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := drgb.path(ctx)
	if err != nil {
		return err
	}
	drgb.sql = query
	return drgb.sqlScan(ctx, v)
}

func (drgb *DeviceRequestGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range drgb.fields {
		if !devicerequest.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := drgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := drgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (drgb *DeviceRequestGroupBy) sqlQuery() *sql.Selector {
	selector := drgb.sql.Select()
	aggregation := make([]string, 0, len(drgb.fns))
	for _, fn := range drgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(drgb.fields)+len(drgb.fns))
		for _, f := range drgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(drgb.fields...)...)
}

// DeviceRequestSelect is the builder for selecting fields of DeviceRequest entities.
type DeviceRequestSelect struct {
	*DeviceRequestQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (drs *DeviceRequestSelect) Scan(ctx context.Context, v interface{}) error {
	if err := drs.prepareQuery(ctx); err != nil {
		return err
	}
	drs.sql = drs.DeviceRequestQuery.sqlQuery(ctx)
	return drs.sqlScan(ctx, v)
}

func (drs *DeviceRequestSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := drs.sql.Query()
	if err := drs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
