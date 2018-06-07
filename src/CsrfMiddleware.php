<?php

namespace bemang\csrf;

use bemang\Session\SessionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CsrfMiddleware implements MiddlewareInterface
{
    /**
     * @var array|\ArrayAccess
     */
    protected $session;

    /**
     * @var string
     */
    protected $sessionKey;

    /**
     * @var string
     */
    protected $formKey;

    /**
     * @var int
     */
    protected $limit;

    public function __construct(SessionInterface $session, int $limit = 50, string $sessionKey = 'csrf.tokens', string $formKey = '__csrf')
    {
        $this->session = $session;
        $this->sessionKey = $sessionKey;
        $this->formKey = $formKey;
        $this->limit = $limit;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (in_array($request->getMethod(), ['PUT', 'POST', 'DELETE'], true)) {
            $params = $request->getParsedBody() ?: [];
            if (!array_key_exists($this->formKey, $params)) {
                //Pas de clé pour le csrf
            }
            if (!in_array($params[$this->formKey], $this->session[$this->sessionKey] ?? [], true)) {
                //Clé fournie invalide
            }
            $this->removeToken($params[$this->formKey]);
        }
        return $handler->handle($request);
    }

    public function generateToken(): string
    {
        //NOTE : Méthode pour stocker le token et autre méthode de génération de token
        $token = bin2hex(random_bytes(16));
        $tokens = $this->session[$this->sessionKey] ?? [];
        $tokens[] = $token;
        $this->session[$this->sessionKey] = $this->limitTokens($tokens);
        return $token;
    }

    protected function removeToken(string $token): void
    {
        $this->session[$this->sessionKey] = array_filter(
            $this->session[$this->sessionKey] ?? [],
            function ($t) use ($token) {
                return $token !== $t;
            }
        );
    }

    public function getSessionKey(): string
    {
        return $this->sessionKey;
    }

    public function getFormKey(): string
    {
        return $this->formKey;
    }

    protected function limitTokens(array $tokens): array
    {
        if (count($tokens) > $this->limit) {
            array_shift($tokens);
        }
        return $tokens;
    }
}
