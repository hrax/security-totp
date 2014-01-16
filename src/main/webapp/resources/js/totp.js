var TOTP = function() {}

TOTP.prototype = {
		_replace: function(data, text) {
			var temp = text;
			for (var k in data) {
				var v = data[k];
				temp = temp.replace(new RegExp("\\{\\{"+k+"\\}\\}", "g"), v);
			}
			return temp;
		},
		
		_form: function(form, success, error) {
			$.ajax({
				url: $(form).attr('action'),
				type: $(form).attr('method'),
				data: $(form).serialize(),
				success: success,
				error: error
			});
		},
		
		show: function(data) {
			var totp = this;
			var html = this._replace(data, $('#template').html());
			$('#wrapper').html(html);
			$("#refresh").click(function(e){
				e.preventDefault();
				$.ajax({
					url: $(this).attr('href'),
					type: 'post',
					success: function(data) {
						if (data.error) {
							alert(data.error);
							return;
						}
						alert(data.refreshed ? "TOTP refreshed." : "TOTP not refreshed.");
					},
					error: function(xhr, err) {
						alert("Unexpected error!");
					}
				})
			});
			$("#destroy").click(function(e){
				e.preventDefault();
				$.ajax({
					url: $(this).attr('href'),
					type: 'post',
					success: function(data) {
						if (data.error) {
							alert(data.error);
							return;
						}
						
						if (!data['destroyed']) {
							alert('TOTP not destroyed.');
							return;
						} else {
							$('#wrapper').empty();
						}
					},
					error: function (xhr, err){
						alert("Unexpected error!");
					}
				});
			});
		},
		
		attach: function() {
			var totp = this;
			$('#generate').submit(function(e){
				e.preventDefault();
				totp._form($(this), function(data){
					if (data['error']) {
						alert(data['error']);
						return;
					}
					totp.show(data);
					$('#generate').find('input[name=username]').val('');
				}, function (xhr, err){
					alert("Unexpected error!");
				});
			});
			$('#verify').submit(function(e){
				e.preventDefault();
				totp._form($(this), function(data){
					if (data['error']) {
						alert(data['error']);
						return;
					}
					if (!data['valid']) {
						alert('Code not valid!');
					} else {
						alert('Code valid!');
					}
					$('#verify').find('input[name=code]').val('');
				}, function (xhr, err){
					alert("Unexpected error!");
				});
			});
		}
		
}