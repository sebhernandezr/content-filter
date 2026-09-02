## Default Permission

Allows the frontend to activate the content-filter system extension, enable and disable the
filter, read its status, and probe a destination with a raw TCP connect for testing the
allowlist.

#### This default permission set includes the following:

- `allow-activate-extension`
- `allow-enable-filter`
- `allow-disable-filter`
- `allow-remove-filter`
- `allow-filter-status`
- `allow-test-connect`

## Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`content-filter:allow-activate-extension`

</td>
<td>

Enables the activate_extension command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:deny-activate-extension`

</td>
<td>

Denies the activate_extension command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:allow-disable-filter`

</td>
<td>

Enables the disable_filter command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:deny-disable-filter`

</td>
<td>

Denies the disable_filter command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:allow-enable-filter`

</td>
<td>

Enables the enable_filter command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:deny-enable-filter`

</td>
<td>

Denies the enable_filter command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:allow-filter-status`

</td>
<td>

Enables the filter_status command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:deny-filter-status`

</td>
<td>

Denies the filter_status command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:allow-remove-filter`

</td>
<td>

Enables the remove_filter command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:deny-remove-filter`

</td>
<td>

Denies the remove_filter command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:allow-test-connect`

</td>
<td>

Enables the test_connect command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`content-filter:deny-test-connect`

</td>
<td>

Denies the test_connect command without any pre-configured scope.

</td>
</tr>
</table>
