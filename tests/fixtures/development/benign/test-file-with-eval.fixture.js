// codesure: SAFE
describe('eval security test', () => {
  it('should detect eval injection', () => {
    const result = scanner.scan('eval(req.body.code)');
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
